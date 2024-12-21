#!venv/bin/python3

##
## wsnic.py
## WebSocket to TAP device proxy server.
##

import os, configparser, argparse, fcntl, struct, socket, time, select, re
from subprocess import run
from collections import deque

from websockets.server import ServerProtocol
from websockets.http11 import Request
from websockets.frames import Frame, Opcode

from scapy.all import DHCP_am
from scapy.base_classes import Net

def mac2str(mac_bytes):
    return ':'.join([mac_bytes.hex()[i:i+2] for i in range(0,12,2)])

class Config:
    def __init__(self):
        self.ws_server_addr = '127.0.0.1'
        self.ws_server_port = 8070
        self.eth_iface = 'eth0'
        self.tap_iface = 'wstap0'
        self.tap_addr = '192.168.2.1/24'
        self.dhcp_domain = None
        self.dhcp_pool = '192.168.2.128/25'
        self.dhcp_network = '192.168.2.0/24'
        self.dhcp_gw = '192.168.2.1'
        self.dhcp_nameserver = ['8.8.8.8', '8.8.4.4']
        self.dhcp_lease_time = 86400
        self.dhcp_renewal_time = 600

    def parse_conf(self, conf_filename):
        with open(conf_filename) as f_in:
            conf_file = f_in.read()
        parser = configparser.ConfigParser(strict=True)
        parser.read_string('[main]\n' + conf_file)
        for opt_name, opt_value in parser.items('main'):
            if hasattr(self, opt_name):
                if opt_name == 'dhcp_nameserver':
                    nameserver = opt_value.split()
                    if len(nameserver) > 2:
                        print(f'{conf_filename}: warning: only 0, 1 or 2 DNS server are supported, ignoring {nameserver[ 2 : ]}')
                    opt_value = nameserver[ : 2 ]
                elif opt_name in ['ws_server_port', 'dhcp_lease_time', 'dhcp_renewal_time']:
                    opt_value = int(opt_value)
                setattr(self, opt_name, opt_value if opt_value != '' else None)
            else:
                print(f'{conf_filename}: warning: unknown option "{opt_name}"')

class FrameQueue:
    def __init__(self):
        self.curr_frame = None
        self.curr_consumed = 0
        self.queue = deque()

    def is_empty(self):
        return self.curr_frame is None and len(self.queue) == 0

    def append(self, data):
        self.queue.appendleft(data)

    def get_frame(self):
        if self.curr_frame is None:
            if len(self.queue) == 0:
                return None
            self.curr_frame = self.queue.pop()
            self.curr_consumed = 0
        elif self.curr_consumed > 0:
            return self.curr_frame[ self.curr_consumed : ]
        return self.curr_frame

    def trim_frame(self, n_bytes):
        if self.curr_frame:
            self.curr_consumed += n_bytes
            if self.curr_consumed >= len(self.curr_frame):
                self.curr_frame = None

class Pollable:
    def __init__(self, server, epoll_flags=select.EPOLLIN):
        self.server = server
        self.config = server.config
        self.epoll = server.epoll
        self.epoll_flags = epoll_flags
        self.fd = None

    def wants_recv(self, do_recv):
        self._wants_flag(do_recv, select.EPOLLIN)

    def wants_send(self, do_send):
        self._wants_flag(do_send, select.EPOLLOUT)

    def _wants_flag(self, wants_flag, flag):
        if wants_flag:
            epoll_flags = self.epoll_flags | flag
        else:
            epoll_flags = self.epoll_flags & ~flag
        if self.epoll_flags != epoll_flags:
            self.epoll_flags = epoll_flags
            self.epoll.modify(self.fd, epoll_flags)

    def open(self, fd):
        self.fd = fd
        self.server.register_pollable(fd, self, self.epoll_flags)

    def close(self):
        if self.fd is not None:
            self.server.unregister_pollable(self.fd)
            self.fd = None

    def send_ready(self):
        pass

    def recv_ready(self):
        pass

    def refresh(self, tm_now):
        pass

class WebSocketServer(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.sock = None

    def open(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.config.ws_server_addr, self.config.ws_server_port))
        self.sock.setblocking(0)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.listen(1)
        super().open(self.sock.fileno())
        print(f'{self.config.ws_server_addr}:{self.config.ws_server_port}: websocket server listening')

    def close(self):
        super().close()
        if self.sock:
            self.sock.close()
            self.sock = None

    def recv_ready(self):
        sock, addr = self.sock.accept()
        sock.setblocking(0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ws_client = WebSocketClient(self.server)
        ws_client.open(sock, addr)
        print(f'{ws_client.addr}: accepted TCP connection')

class WebSocketClient(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.proto = ServerProtocol()
        self.out = FrameQueue()     ## frames waiting to be send to websocket
        self.last_recv_tm = time.time()
        self.last_ping_tm = self.last_recv_tm
        self.close_when_out_drained = False
        self.sock = None
        self.addr = None
        self.mac = None

    def open(self, sock, addr):
        self.sock = sock
        self.addr = f'{addr[0]}:{addr[1]}'
        super().open(sock.fileno())

    def close(self):
        super().close()
        if self.mac is not None:
            self.server.unregister_ws_client(self)
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def send_ready(self):
        eth_frame = self.out.get_frame()
        if eth_frame is None:
            self.wants_send(False)
            if self.close_when_out_drained:
                self.close()
                print(f'{self.addr}: disconnected')
        else:
            try:
                n_sent = self.sock.send(eth_frame)
                self.out.trim_frame(n_sent)
            except OSError as e:
                self.close()
                print(f'{self.addr}: disconnected at send(), reason: {e}')

    def recv_ready(self):
        try:
            ws_frame = self.sock.recv(65535)
        except OSError as e:
            ws_frame = b''
            print(f'{self.addr}: disconnected at recv(), reason: {e}')
        if ws_frame:
            self.recv(ws_frame)
            self.last_recv_tm = time.time()
        else:
            self.close()

    def refresh(self, tm_now):
        if tm_now - self.last_recv_tm > 30 and tm_now - self.last_ping_tm > 30:
            self.last_ping_tm = tm_now
            self.proto.send_ping(b'PING')
            self._pump()

    def send(self, eth_frame):
        self.proto.send_binary(eth_frame)
        self._pump()

    def recv(self, ws_data):
        if ws_data:
            self.proto.receive_data(ws_data)
        else:
            self.proto.receive_eof()
        self._pump()

        for ev in self.proto.events_received():
            if isinstance(ev, Frame):
                if ev.opcode == Opcode.BINARY:
                    src_mac = ev.data[ 6 : 12 ]
                    if self.mac != src_mac:
                        self.server.register_ws_client(self, src_mac)
                        print(f'{self.addr}: registered MAC {mac2str(src_mac)}')
                    self.server.tap_dev.send(ev.data)
                elif ev.opcode == Opcode.PING:
                    self.proto.send_pong(ev.data)
                elif ev.opcode != Opcode.PONG and ev.opcode != Opcode.CLOSE:
                    print(f'{self.addr}: received unhandled ws packet: {ev.opcode} {ev}')
            elif isinstance(ev, Request):
                self.proto.send_response(self.proto.accept(ev))
                print(f'{self.addr}: accepted WebSocket connection')
            else:
                print(f'{self.addr}: *** received unexpected ws packet: {ev}')
            self._pump()

    def _pump(self):
        ## call this method immediately after any of the receive_*(), send_*(), or fail() methods.
        data_to_send = self.proto.data_to_send()
        if len(data_to_send) > 0:
            was_empty = self.out.is_empty()
            for data in data_to_send:
                if len(data):
                    self.out.append(data)
                elif self.out.is_empty():
                    self.close()
                else:
                    self.close_when_out_drained = True
            if was_empty:
                self.wants_send(True)

class TapDevice(Pollable):
    @staticmethod
    def install_tap(c):
        run(['ip', 'tuntap', 'add', 'dev', c.tap_iface, 'mode', 'tap'], check=True)
        run(['ip', 'address', 'add', c.tap_addr, 'dev', c.tap_iface], check=True)
        run(['ip', 'link', 'set', 'dev', c.tap_iface, 'up'], check=True)
        run(['iptables', '-A', 'POSTROUTING', '-t', 'nat', '-o', c.eth_iface, '-j', 'MASQUERADE'], check=True)
        run(['iptables', '-A', 'FORWARD', '-i', c.eth_iface, '-o', c.tap_iface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)
        run(['iptables', '-A', 'FORWARD', '-i', c.tap_iface, '-o', c.eth_iface, '-j', 'ACCEPT'], check=True)

    @staticmethod
    def uninstall_tap(c):
        run(['iptables', '-D', 'FORWARD', '-i', c.tap_iface, '-o', c.eth_iface, '-j', 'ACCEPT'])
        run(['iptables', '-D', 'FORWARD', '-i', c.eth_iface, '-o', c.tap_iface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
        run(['iptables', '-D', 'POSTROUTING', '-t', 'nat', '-o', c.eth_iface, '-j', 'MASQUERADE'])
        run(['ip', 'link', 'set', 'dev', c.tap_iface, 'down'])
        run(['ip', 'address', 'del', c.tap_addr, 'dev', c.tap_iface])
        run(['ip', 'tuntap', 'del', 'dev', c.tap_iface, 'mode', 'tap'])

    def __init__(self, server):
        super().__init__(server)
        self.tap_installed = False  ## True: TAP device has been installed
        self.dhcp_server = None
        self.out = FrameQueue()     ## frames waiting to be send to tap device

    def open(self):
        c = self.config
        print(f'{c.tap_iface}: installing TAP device with NAT peer {c.eth_iface}')
        self.install_tap(c)
        self.tap_installed = True

        print(f'{c.tap_iface}: opening TAP device using /dev/net/tun')
        TUNSETIFF, IFF_TAP, IFF_NO_PI = 0x400454ca, 0x0002, 0x1000
        self.fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        os.set_blocking(self.fd, False)
        fcntl.ioctl(
            self.fd,
            TUNSETIFF,
            struct.pack('16sH', bytes(c.tap_iface, 'utf-8'), IFF_TAP | IFF_NO_PI))

        print(f'{c.tap_iface}: starting DHCP server on TAP device')
        dhcp_options = {}
        if c.dhcp_domain:
            dhcp_options['domain'] = c.dhcp_domain
        if c.dhcp_nameserver:
            dhcp_options['nameserver'] = c.dhcp_nameserver[0]
            if len(c.dhcp_nameserver) > 1:
                dhcp_options['name_server'] = c.dhcp_nameserver[1]
        dhcp_server = DHCP_am(iface = c.tap_iface, pool = Net(c.dhcp_pool), network = c.dhcp_network,
            gw = c.dhcp_gw, lease_time = c.dhcp_lease_time, renewal_time = c.dhcp_renewal_time,
            **dhcp_options)
        self.dhcp_server = dhcp_server.bg()

        super().open(self.fd)

    def close(self):
        if self.dhcp_server:
            if self.dhcp_server.running:
                self.dhcp_server.stop()
                self.dhcp_server.join()
            self.dhcp_server = None
        fd = self.fd
        super().close()
        if fd is not None:
            os.close(fd)
        if self.tap_installed:
            self.uninstall_tap(self.config)
            self.tap_installed = False

    def send(self, eth_frame):
        if len(eth_frame):
            was_empty = self.out.is_empty()
            self.out.append(eth_frame)
            if was_empty:
                self.wants_send(True)

    def send_ready(self):
        eth_frame = self.out.get_frame()
        if eth_frame is None:
            self.wants_send(False)
        else:
            self.out.trim_frame(os.write(self.fd, eth_frame))

    def recv_ready(self):
        self.server.relay_to_ws_client(os.read(self.fd, 65535))

class WsNicServer:
    def __init__(self, config):
        self.config = config
        self.epoll = select.epoll()
        self.pollables = {}     ## dict(int fd => Pollable pollable)
        self.mac2ws = {}        ## dict(bytes mac[6] => WsConnection ws_conn)
        self.tap_dev = None
        self.ws_server = None

    def register_pollable(self, fd, pollable, epoll_flags):
        if fd in self.pollables:
            print(f'warning: fd {fd} already in use by pollable {self.pollables[fd]}, overwriting!')
        self.pollables[fd] = pollable
        self.epoll.register(fd, epoll_flags)

    def unregister_pollable(self, fd):
        if fd is not None:
            try:
                self.epoll.unregister(fd)
            except FileNotFoundError:
                pass
            if fd in self.pollables:
                del self.pollables[fd]

    def register_ws_client(self, ws_client, mac):
        self.unregister_ws_client(ws_client)
        self.mac2ws[mac] = ws_client
        ws_client.mac = mac

    def unregister_ws_client(self, ws_client):
        if ws_client.mac is not None:
            del self.mac2ws[ws_client.mac]
            ws_client.mac = None

    def relay_to_ws_client(self, eth_frame):
        dst_mac = eth_frame[ : 6 ]
        ws_client = self.mac2ws.get(dst_mac, None)
        if ws_client:
            ws_client.send(eth_frame)
        elif dst_mac[0] & 0x1:
            ## LSB in first octet: 0=UNICAST, 1=MULTICAST (and also BROADCAST with all octets being 0xff)
            for ws_client in self.mac2ws.values():
                ws_client.send(eth_frame)

    def run(self):
        self.tap_dev = TapDevice(self)
        self.tap_dev.open()

        self.ws_server = WebSocketServer(self)
        self.ws_server.open()

        print('wsnic ready, press CTRL+C to exit')
        last_refresh_tm = time.time()
        terminated = False
        while not terminated:
            poll_events = self.epoll.poll(2) ## blocking wait for epoll events for up to 2 seconds
            tm_now = time.time()
            for fd, ev in poll_events:
                pollable = self.pollables[fd]
                if ev & select.EPOLLIN:
                    pollable.recv_ready()
                elif ev & select.EPOLLOUT:
                    pollable.send_ready()
                elif ev & select.EPOLLHUP:
                    if pollable == self.tap_dev or pollable == self.ws_server:
                        pollable_name = 'TAP device file' if pollable == self.tap_dev else 'WebSocket server socket'
                        print(f'*** received unexpected hangup from {pollable_name}, terminating')
                        terminated = True
                        break
                    else:
                        pollable.close()
            if tm_now - last_refresh_tm > 5:
                for pollable in self.pollables.values():
                    pollable.refresh(tm_now)
                last_refresh_tm = tm_now

    def shutdown(self):
        if self.ws_server:
            self.ws_server.close()
            self.ws_server = None
        if self.tap_dev:
            self.tap_dev.close()
            self.tap_dev = None
        self.epoll.close()

def main():
    parser = argparse.ArgumentParser(prog='wsnic', description='WebSocket to TAP device proxy server.')
    parser.add_argument('-c', help='use configuration file CONF_FILE (default: wsnic.conf)', default='wsnic.conf', dest='conf', metavar='CONF_FILE')
    parser.add_argument('-r', help='release TAP device resources', dest='release', action='store_true')
    args = parser.parse_args()

    config = Config()
    if os.path.isfile(args.conf):
        config.parse_conf(args.conf)

    if args.release:
        TapDevice.uninstall_tap(config)
    else:
        server = WsNicServer(config)
        try:
            server.run()
        except KeyboardInterrupt:
            print()
        finally:
            server.shutdown()

if __name__ == '__main__':
    main()
