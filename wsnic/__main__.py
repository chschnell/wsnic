##
## wsnic - WebSocket to TAP device proxy server
## Main entry point.
##

import os, re, configparser, argparse, time, select

from wsnic.websock_srv import WebSocketServer
from wsnic.tap_dev import TapBridge
from wsnic.dhcp_srv import DhcpNetwork

class Config:
    def __init__(self):
        self.ws_server_addr = '127.0.0.1'
        self.ws_server_port = 8070
        self.eth_iface = 'eth0'
        self.bridge_subnet = '192.168.2.0/24'
        self.bridge_restrict_inbound = True
        self.dhcp_gateway = None
        self.dhcp_domain_name = None
        self.dhcp_domain_name_server = ['8.8.8.8', '8.8.4.4']
        self.dhcp_lease_time = 86400

    def parse_conf(self, conf_filename):
        with open(conf_filename) as f_in:
            conf_file = f_in.read()
        parser = configparser.ConfigParser(strict=True)
        parser.read_string('[main]\n' + conf_file)
        for opt_name, opt_value in parser.items('main'):
            if hasattr(self, opt_name):
                if opt_name in ['dhcp_domain_name_server']:
                    opt_value = re.split(r'[,:;\s]+', opt_value)
                elif opt_name in ['ws_server_port', 'dhcp_lease_time']:
                    opt_value = int(opt_value)
                elif opt_name in ['bridge_restrict_inbound']:
                    opt_value = opt_value.lower() == 'true'
                elif opt_value == '':
                    opt_value = None
                setattr(self, opt_name, opt_value)
            else:
                print(f'{conf_filename}: warning: unknown option "{opt_name}" ignored')

class WsnicServer:
    def __init__(self, config):
        self.config = config
        self.dhcp_network = DhcpNetwork(config)
        self.tap_bridge = None      ## TapBridge
        self.ws_server = None       ## WebSocketServer
        self.pollables = {}         ## dict(int fd => Pollable pollable)
        self.epoll = select.epoll()

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

    def run(self):
        self.tap_bridge = TapBridge(self, 'wsnicbr0')
        self.tap_bridge.open()

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
                    if pollable == self.ws_server:
                        print(f'*** received unexpected hangup from WebSocket server socket, terminating')
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
        if self.tap_bridge:
            self.tap_bridge.close()
            self.tap_bridge = None
        self.epoll.close()

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
