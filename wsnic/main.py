##
## wsnic - WebSocket to virtual network device proxy server for linux
## Main entry point.
##

import os, re, logging, configparser, argparse, textwrap, time, ipaddress, select, shutil, subprocess

from wsnic.websock import WebSocketServer
from wsnic.stunnel import StunnelProxyServer
from wsnic.nbe_brtap import BridgedTapNetworkBackend

logger = logging.getLogger('main')

class WsnicConfig:
    def __init__(self, args):
        def parse_option(opt_name, opt_value):
            if opt_name in ['dhcp_nameserver']:
                return re.split(r'[,:;\s]+', opt_value)
            elif opt_name in ['ws_port', 'wss_port', 'dhcp_lease_time']:
                return int(opt_value)
            elif opt_name in ['enable_inet', 'disable_dhcp']:
                return opt_value.lower() in ['yes', 'true', 't', '1']
            elif opt_value == '':
                return None
            else:
                return opt_value

        ## declare options that can be modified by CLI or configuraton file
        self.ws_address = None          ## str, WebSocket (Secure) TCP server bind address
        self.ws_port = 8086             ## int, WebSocket TCP server port (ws://)
        self.wss_port = 8087            ## int, WebSocket Secure TCP server port (wss://)
        self.wss_certificate = None     ## str, PEM encoded certificate file, enables WebSocket Secure if defined
        self.wss_private_key = None     ## str, PEM encoded private key file, optional
        self.subnet = '192.168.86.0/24' ## str, defines bridge, gateway and DHCP server IP, and the DHCP pool
        self.enable_inet = False        ## bool, True: use NAT masquerading to connect bridge to inet_iface
        self.inet_iface = None          ## str, name of an interface that provides Internet access
        self.disable_dhcp = False       ## bool, True: disable DHCP, False: use dnsmasq for DHCP/DNS
        self.dhcp_lease_file = None     ## str, DHCP lease database file, use temp file if undefined
        self.dhcp_lease_time = 86400    ## int, DHCP lease time in seconds
        self.dhcp_domain_name = None    ## str, local domain name published in DHCP replies
        self.dhcp_nameserver = None     ## array(str), list of DNS server IPs

        ## check for Docker: Docker creates "/.dockerenv", podman "/run/.containerenv"
        is_docker_env = os.path.isfile('/.dockerenv') or os.path.isfile('/run/.containerenv')

        ## parse and apply configuration file options first
        wsnic_conf = args.wsnic_conf
        if wsnic_conf is None and os.path.isfile('wsnic.conf'):
            wsnic_conf = 'wsnic.conf'
        if wsnic_conf:
            logger.info(f'reading wsnic configuration from {wsnic_conf}')
            with open(wsnic_conf) as f_in:
                conf_file = f_in.read()
            parser = configparser.ConfigParser(strict=True)
            parser.read_string('[main]\n' + conf_file)
            for opt_name, opt_value in parser.items('main'):
                if hasattr(self, opt_name):
                    setattr(self, opt_name, parse_option(opt_name, opt_value))
                else:
                    logger.warning(f'{wsnic_conf}: unknown option "{opt_name}" ignored!')

        ## parse and apply command line arguments next
        for opt_name, opt_value in args.__dict__.items():
            if opt_value is not None and hasattr(self, opt_name):
                setattr(self, opt_name, parse_option(opt_name, opt_value))

        ## set defaults last
        if self.ws_address is None:
            if is_docker_env:
                self.ws_address = '0.0.0.0'
            else:
                self.ws_address = '127.0.0.1'
        if self.enable_inet and self.inet_iface is None:
            inet_iface = subprocess.getoutput('ip route | grep "^default " | grep -Po "(?<=dev )[^ ]+"')
            if inet_iface:
                self.inet_iface = inet_iface
        if self.wss_certificate is None and os.path.isfile('cert/cert.crt'):
            self.wss_certificate = os.path.abspath('cert/cert.crt')
        if self.wss_private_key is None and os.path.isfile('cert/cert.key'):
            self.wss_private_key = os.path.abspath('cert/cert.key')

        ## derive network settings dynamically from self.subnet
        ip_subnet = ipaddress.ip_network(self.subnet)
        hosts = ip_subnet.hosts()
        server_addr = str(next(hosts))
        host_addrs = [str(addr) for addr in hosts]
        broadcast_addr = str(ip_subnet.broadcast_address)
        netmask = str(ip_subnet.netmask)

        ## set dhcp_nameserver default
        if not self.disable_dhcp and not self.dhcp_nameserver:
            self.dhcp_nameserver = [server_addr]

        if logger.isEnabledFor(logging.DEBUG):
            options = [f'{opt_name} = {opt_value}' for opt_name, opt_value in self.__dict__.items()]
            logger.debug('wsnic configuration:\n' + '\n'.join(options))

        self.is_docker_env = is_docker_env   ## bool, True: running under Docker or Docker-like environment
        self.server_addr = server_addr       ## str, network's bridge, gateway and DHCP server IP address
        self.host_addrs = host_addrs         ## array(str), network's DHCP host IP address pool
        self.broadcast_addr = broadcast_addr ## str, network's broadcast IP address
        self.netmask = netmask               ## str, network's netmask (in IP-notation)

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
        self.netbe = self.netbe_class(self)
        self.netbe.open()

        self.ws_server = WebSocketServer(self)
        self.ws_server.open()

        if self.config.wss_certificate:
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
        if self.stunnel:
            self.stunnel.close()
        if self.ws_server:
            self.ws_server.close()
            self.ws_server = None
        if self.netbe:
            self.netbe.close()
            self.netbe = None
        self.epoll.close()

def main():
    def format_help(text):
        lines = []
        for para in text.split('\n'):
            if para == '':
                lines.append(para)
            else:
                for line in textwrap.wrap(para, break_long_words=False, replace_whitespace=False, width=60):
                    lines.append(line)
        return '\n'.join(lines)

    help_formatter = lambda prog: argparse.RawTextHelpFormatter(prog, max_help_position=10, indent_increment=4)

    parser = argparse.ArgumentParser(prog='wsnic',
        description='WebSocket to virtual network device proxy server.',
        formatter_class=help_formatter)
    parser.add_argument('-v', help='Output verbose log messages.',
        action='store_true', dest='verbose')
    parser.add_argument('-q', help='Output warning and error log messages only.',
        action='store_true', dest='quiet')
    parser.add_argument('-c', dest='wsnic_conf', metavar='CFGFILE', help=format_help(
        'Use configuration file CFGFILE, default: wsnic.conf (if exists).'))
    parser.add_argument('-a', '--ws-address', metavar='ADDR', help=format_help(
        'WebSocket server address.\n'
        'Use 127.0.0.1 if wsnic runs on the same machine as the WebSocket client'
        ' (browser), or 0.0.0.0 to make wsnic available in the network.\n'
        'Default: 0.0.0.0 under Docker or 127.0.0.1.'))
    parser.add_argument('--ws-port', metavar='PORT', help=format_help(
        'WebSocket server port (ws://), default: 8086.'))
    parser.add_argument('--wss-port', metavar='PORT', help=format_help(
        'WebSocket Secure server port (wss://), default: 8087.'))
    parser.add_argument('-r', '--wss-certificate', metavar='CRTFILE', help=format_help(
        'Absolute path of a PEM formatted file containing either just the'
        ' public server certificate or an entire certificate chain'
        ' including public key, private key, and root certificates.\n'
        'Optional, default: "cert/cert.crt" (if exists).'))
    parser.add_argument('-k', '--wss-private-key', metavar='KEYFILE', help=format_help(
        'Absolute path of a PEM formatted file containing only the private'
        ' key of the server certificate.\n'
        'Optional, default: "cert/cert.key" (if exists).'))
    parser.add_argument('-s', '--subnet', metavar='SUBNET', help=format_help(
        'The wsnic subnet in CIDR notation, default: 192.168.86.0/24.\n'
        'The subnet\'s first and last IP addresses are reserved for'
        ' network and broadcast addresses.'
        ' The subnet\'s second IP is reserved for the bridge device'
        ' (also gateway and DHCP server IP).'
        ' The remaining IP addresses are used for the DHCP address'
        ' pool.\n'
        'Example for the default subnet:\n'
        '- Network address: 192.168.86.0\n'
        '- Broadcast address: 192.168.86.255\n'
        '- Bridge/gateway/DHCPD address: 192.168.86.1\n'
        '- DHCP address pool: 192.168.86.2 ... 192.168.86.254\n'
        'The default subnet might conflict with your local network'
        ' configuration and must then be changed accordingly.'))
    parser.add_argument('-i', '--enable-inet', action='store_const', const='1', help=format_help(
        'Grant bridge access to the host\'s network (including Internet if'
        ' available) using inet_iface.'))
    parser.add_argument('-f', '---inet-iface', metavar='IFACE', help=format_help(
        'Interface name of a physical network device that provides access to'
        ' the Internet (for example "eth0" or "enp0s3").\n'
        'wsnic will try to auto-detect this interface, this option is only'
        ' needed to force an interface name in case detection fails.'
        ' This option only takes effect if CLI option -i is also present.\n'
        'Optional, default (Docker only): "eth0".'))
    parser.add_argument('--disable-dhcp', action='store_const', const='1', help=format_help(
        'Disable DHCP/DNS service using dnsmasq.'))
    parser.add_argument('--dhcp-lease-file', metavar='DBFILE', help=format_help(
        'DHCP lease database file path, default: undefined.\n'
        'If undefined, wsnic uses a temporary file which will be deleted'
        ' on close.'))
    parser.add_argument('-t', '---dhcp-lease-time', metavar='SECONDS', help=format_help(
        'DHCP lease time in seconds, default: 86400 (24 hours).'))
    parser.add_argument('-n', '---dhcp-domain-name', metavar='NAME', help=format_help(
        'Domain Name of this subnet published in DHCP replies.\n'
        'Optional, default: undefined.'))
    parser.add_argument('-d', '--dhcp-nameserver', metavar='IPLIST', help=format_help(
        'Comma-separated list of Domain Name Server (DNS) IP address(es)'
        ' published in DHCP replies, for example:\n    "8.8.8.8, 8.8.4.4"\n'
        'If undefined, the bridge\'s IP address is used as the DNS address'
        ' (which gets handled by dnsmasq).\n'
        'Optional, default: undefined.'))
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f'error: must be root')
        return
    elif args.wsnic_conf and not os.path.isfile(args.wsnic_conf):
        print(f'error: configuration file "{args.wsnic_conf}" not found')
        return

    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.WARNING
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s %(name)s: %(message)s', datefmt='%H:%M:%S')
    logging.getLogger('websockets').setLevel(logging.WARNING)   ## suppress INFO and DEBUG log messages in websockets library

    config = WsnicConfig(args)

    if shutil.which('ip') is None:
        print(f'error: executable file "ip" not found (Debian: install apt package iproute2)')
        return
    elif shutil.which('iptables') is None:
        print(f'error: executable file "iptables" not found (Debian: install apt package iptables)')
        return
    elif not config.disable_dhcp and shutil.which('dnsmasq') is None:
        print(f'error: executable file "dnsmasq" not found (Debian: install apt package dnsmasq)')
        return
    elif config.enable_inet and not config.inet_iface:
        print(f'error: network interface must be specified, see CLI option "-f"')
        return
    elif config.wss_certificate and not os.path.isfile(config.wss_certificate):
        print(f'error: certificate file "{config.wss_certificate}" not found, see CLI option "-r"')
        return
    elif config.wss_private_key and not os.path.isfile(config.wss_private_key):
        print(f'error: private key file "{config.wss_private_key}" not found, see CLI option "-k"')
        return

    server = WsnicServer(config, BridgedTapNetworkBackend)
    try:
        server.run()
    except KeyboardInterrupt:
        print()
    finally:
        server.shutdown()
