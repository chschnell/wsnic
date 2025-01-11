##
## wsnic - WebSocket to virtual network device proxy server for linux
## Main entry point.
##

import os, re, logging, configparser, argparse, time, ipaddress, select, shutil

from wsnic import sysctl
from wsnic.websock import WebSocketServer
from wsnic.stunnel import StunnelProxyServer
from wsnic.nbe_brtap import BridgedTapNetworkBackend

logger = logging.getLogger('main')

class WsnicConfig:
    def __init__(self, conf_filename):
        ## settings available in wsnic.conf:
        self.ws_server_addr = '127.0.0.1'
        self.ws_server_port = 8070
        self.eth_iface = 'eth0'
        self.subnet = '192.168.2.0/24'
        self.wss_server_port = 8071
        self.wss_server_cert = None
        self.wss_server_key = None
        self.dhcp_service = 'dnsmasq'
        self.dhcp_lease_file = None
        self.dhcp_lease_time = 86400
        self.dhcp_domain_name = None
        self.dhcp_domain_name_server = None

        if os.path.isfile(conf_filename):
            with open(conf_filename) as f_in:
                conf_file = f_in.read()
            parser = configparser.ConfigParser(strict=True)
            parser.read_string('[main]\n' + conf_file)
            for opt_name, opt_value in parser.items('main'):
                if hasattr(self, opt_name):
                    if opt_name in ['dhcp_domain_name_server']:
                        opt_value = re.split(r'[,:;\s]+', opt_value)
                    elif opt_name in ['ws_server_port', 'wss_server_port', 'dhcp_lease_time']:
                        opt_value = int(opt_value)
                    elif opt_value == '':
                        opt_value = None
                    setattr(self, opt_name, opt_value)
                else:
                    logger.warning(f'{conf_filename}: unknown option "{opt_name}" ignored')

        ## network settings dynamically derived from self.subnet:
        ip_subnet = ipaddress.ip_network(self.subnet)
        hosts = ip_subnet.hosts()
        self.server_addr = str(next(hosts))
        self.host_addrs = [str(addr) for addr in hosts]
        self.broadcast_addr = str(ip_subnet.broadcast_address)
        self.netmask = str(ip_subnet.netmask)
        if not self.dhcp_domain_name_server:
            self.dhcp_domain_name_server = [self.server_addr]

class WsnicServer:
    def __init__(self, config, netbe_class):
        self.config = config            ## WsnicConfig
        self.netbe_class = netbe_class  ## NetworkBackend class
        self.netbe = None               ## NetworkBackend, instance of netbe_class created in run()
        self.ws_server = None           ## WebSocketServer, created in run()
        self.stunnel = None             ## StunnelProxyServer, created in run()
        self.epoll = select.epoll()     ## single epoll object for all open sockets and files
        self.pollables = {}             ## dict(int fd => Pollable pollable)

    def register_pollable(self, fd, pollable, epoll_flags):
        if fd in self.pollables:
            logger.warning(f'warning: fd {fd} already in use by pollable {self.pollables[fd]}, overwriting!')
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

    def run(self):
        sysctl.write('net/ipv4/ip_forward', 1)
        sysctl.write('net/ipv4/conf/all/forwarding', 1)
        sysctl.write('net/ipv4/conf/default/forwarding', 1)
        sysctl.write('net/ipv6/conf/all/forwarding', 1)
        sysctl.write('net/ipv6/conf/default/forwarding', 1)

        self.netbe = self.netbe_class(self)
        self.netbe.open()

        self.ws_server = WebSocketServer(self)
        self.ws_server.open()

        if self.config.wss_server_cert:
            self.stunnel = StunnelProxyServer(self.config)
            self.stunnel.open()

        last_refresh_tm = time.time()
        terminated = False
        while not terminated:
            poll_events = self.epoll.poll(2)    ## blocking wait for up to 2 seconds
            tm_now = time.time()
            for fd, ev in poll_events:
                pollable = self.pollables.get(fd, None)
                if not pollable:
                    continue
                if ev & select.EPOLLIN:
                    pollable.recv_ready()
                if ev & select.EPOLLOUT:
                    pollable.send_ready()
                if ev & select.EPOLLHUP:
                    if pollable == self.ws_server:
                        logger.error('received unexpected hangup from WebSocket server socket, terminating')
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
        if self.netbe:
            self.netbe.close()
            self.netbe = None
        if self.stunnel:
            self.stunnel.close()
        self.epoll.close()
        sysctl.restore_values()

def main():
    parser = argparse.ArgumentParser(prog='wsnic', description='WebSocket to virtual network device proxy server.')
    parser.add_argument('-n', help='use network backend NETBE (currently only default "brtap" supported)',
        choices=['brtap'], default='brtap', dest='netbe', metavar='NETBE')
    parser.add_argument('-c', help='use configuration file CONF_FILE (default: wsnic.conf)',
        default='wsnic.conf', dest='conf', metavar='CONF_FILE')
    parser.add_argument('-v', help='print verbose output', action='store_true', dest='verbose')
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s %(name)s: %(message)s', datefmt='%H:%M:%S')
    logging.getLogger('websockets').setLevel(logging.WARNING)   ## suppress INFO and DEBUG log messages in websockets library

    config = WsnicConfig(args.conf)

    if os.geteuid() != 0:
        print(f'error: must be run by root')
        return
    elif shutil.which('ip') is None:
        print(f'ip: file not found (Debian: install apt package iproute2)')
        return
    elif shutil.which('iptables') is None:
        print(f'iptables: file not found (Debian: install apt package iptables)')
        return
    elif config.dhcp_service == 'dnsmasq' and shutil.which('dnsmasq') is None:
        print(f'dnsmasq: file not found (Debian: install apt package dnsmasq)')
        return

    netbe_class = None
    if args.netbe == 'brtap':
        netbe_class = BridgedTapNetworkBackend

    server = WsnicServer(config, netbe_class)
    try:
        server.run()
    except KeyboardInterrupt:
        print()
    finally:
        server.shutdown()

if __name__ == '__main__':
    main()
