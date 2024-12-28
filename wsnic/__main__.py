##
## wsnic - WebSocket to TAP device proxy server
## Main entry point.
##

import os, re, configparser, argparse, time, select

from wsnic.websock_srv import WebSocketServer
from wsnic.tap_dev import TapDevice
from wsnic.dhcp_srv import DhcpNetwork

class Config:
    def __init__(self):
        self.ws_server_addr = '127.0.0.1'
        self.ws_server_port = 8070
        self.eth_iface = 'eth0'

        self.dhcp_network = '192.168.2.0/24'
        self.dhcp_gateway = None
        self.dhcp_domain = None
        self.dhcp_nameserver = ['8.8.8.8', '8.8.4.4']
        self.dhcp_lease_time = 86400

    def parse_conf(self, conf_filename):
        with open(conf_filename) as f_in:
            conf_file = f_in.read()
        parser = configparser.ConfigParser(strict=True)
        parser.read_string('[main]\n' + conf_file)
        for opt_name, opt_value in parser.items('main'):
            if hasattr(self, opt_name):
                if opt_name in ['dhcp_nameserver']:
                    opt_value = re.split(r'[,:;\s]+', opt_value)
                elif opt_name in ['ws_server_port', 'dhcp_lease_time']:
                    opt_value = int(opt_value)
                elif opt_value == '':
                    opt_value = None
                setattr(self, opt_name, opt_value)
            else:
                print(f'{conf_filename}: warning: unknown option "{opt_name}" ignored')

class WsnicServer:
    def __init__(self, config):
        self.config = config
        self.dhcp_network = DhcpNetwork(config)
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
        if os.path.isfile('/proc/sys/net/ipv4/ip_forward'):
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f_out:
                f_out.write('1\n')

        self.tap_dev = TapDevice(self)
        self.tap_dev.open(self.config.eth_iface, self.dhcp_network.server_ip, self.dhcp_network.netmask)

        self.ws_server = WebSocketServer(self)
        self.ws_server.open()

        print('wsnic ready, press CTRL+C to exit')
        last_refresh_tm = time.time()
        terminated = False
        while not terminated:
            poll_events = self.epoll.poll(2)    ## blocking wait for up to 2 seconds
            tm_now = time.time()
            for fd, ev in poll_events:
                pollable = self.pollables[fd]
                if ev & select.EPOLLIN:
                    pollable.recv_ready()
                if ev & select.EPOLLOUT:
                    pollable.send_ready()
                if ev & select.EPOLLHUP:
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
        print('wsnic closed')

def main():
    parser = argparse.ArgumentParser(prog='wsnic', description='WebSocket to TAP device proxy server.')
    parser.add_argument('-c', help='use configuration file CONF_FILE (default: wsnic.conf)',
        default='wsnic.conf', dest='conf', metavar='CONF_FILE')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f'must be root to execute {parser.prog}')
        return

    config = Config()
    if os.path.isfile(args.conf):
        config.parse_conf(args.conf)

    server = WsnicServer(config)
    try:
        server.run()
    except KeyboardInterrupt:
        print()
    finally:
        server.shutdown()

if __name__ == '__main__':
    main()