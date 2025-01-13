##
## wsnic - WebSocket to TAP device proxy server
## Shared package classes.
##

import os, logging, random, subprocess, struct

from select import EPOLLIN, EPOLLOUT
from collections import deque

def mac2str(mac):
    mac = mac.hex()
    return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])

def random_private_mac():
    ## Return a random private 48-bit unicast MAC address.
    ##
    ## The two least significant bits of the most significant byte in MAC
    ## addresses are reserved:
    ##
    ## - bit 1: "0" for unicast and "1" for multicast MACs
    ## - bit 2: "0" for globally unique and "1" for locally administered MACs
    ##
    ## The MAC address of any Network Interface Card (NIC) must be unicast.
    ## That leaves 2^46 (out of the total of 2^48) MACs for locally
    ## administered (private) MACs which can be freely assigned to NICs.
    ##
    ## Since MACs are usually denoted in hex with the most significant byte
    ## first, any private MAC must match one of these 4 patterns:
    ##
    ##     x2:xx:xx:xx:xx:xx
    ##     x6:xx:xx:xx:xx:xx
    ##     xA:xx:xx:xx:xx:xx
    ##     xE:xx:xx:xx:xx:xx
    ##
    ## Looking at the 2nd nibble of the most significant byte in more detail:
    ##
    ##       +---- 1: private MAC
    ##       |+--- 0: unicast MAC
    ##       ||
    ##     0010 =  2 = 0x2
    ##     0110 =  6 = 0x6
    ##     1010 = 10 = 0xA
    ##     1110 = 14 = 0xE
    ##
    mac_addr = bytearray(random.randbytes(6))
    mac_addr[0] = (mac_addr[0] & ~0x01) | 0x02
    return bytes(mac_addr)

ETH_TYPES = {
    0x0800: 'IPv4',
    0x86DD: 'IPv6',
    0x0806: 'ARP',
    0x88E1: 'HPlug',    ## HomePlug Specification AV MME
    0x8912: 'HPlug-M'   ## Ethertype used for mediaxtream Specification protocols
}

IP_PROTOS = {
    0: 'IPv6-HOPOPT',
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
}

def log_eth_frame(tag, eth_frame, logger):
    dst_mac, src_mac, eth_type, ip_proto = struct.unpack_from('!6s6sH9xB10x', eth_frame)
    eth_type = ETH_TYPES.get(eth_type, hex(eth_type))
    ip_proto = IP_PROTOS.get(ip_proto, ip_proto)
    logger.info(f'{tag} {mac2str(src_mac)}->{mac2str(dst_mac)} eth_type={eth_type} ip_proto={ip_proto} len={len(eth_frame)}')

class Sysctl:
    def __init__(self):
        self.enabled = True
        self.old_values = {}

    def disable(self):
        self.enabled = False

    def write(self, path, value):
        if not self.enabled:
            return False
        path = f'/proc/sys/{path}'
        if os.path.isfile(path):
            if path not in self.old_values:
                with open(path, 'r') as f_in:
                    self.old_values[path] = f_in.read()
            with open(path, 'w') as f_out:
                f_out.write(f'{value}\n')
            return True
        return False

    def restore_values(self):
        for path, value in self.old_values.items():
            with open(path, 'w') as f_out:
                f_out.write(value)

sysctl = Sysctl()

class Exec:
    def __init__(self, logger, check=False):
        self.logger = logger
        self.check = check

    def __call__(self, cmdline, check=None):
        if isinstance(cmdline, str):
            cmdline = cmdline.split(' ')
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f'$ {" ".join(cmdline)}')
        subprocess.run(cmdline, check=self.check if check is None else check)

class Pollable:
    ## Base class that wraps an open file descriptor fd for epoll()
    ## fd can be any file type supported by epoll(), for example socket filenos or TAP files.

    def __init__(self, server, epoll_flags=EPOLLIN):
        self.server = server
        self.config = server.config
        self.netbe = server.netbe
        self.epoll = server.epoll
        self.epoll_flags = epoll_flags
        self.fd = None

    def open(self, fd):
        self.fd = fd
        self.server.register_pollable(fd, self, self.epoll_flags)

    def close(self):
        if self.fd is not None:
            self.server.unregister_pollable(self.fd)
            self.fd = None

    def wants_recv(self, do_recv):
        ## add/remove self.fd to/from epoll's observed set of input-fds
        self._wants_flag(do_recv, EPOLLIN)

    def wants_send(self, do_send):
        ## add/remove self.fd to/from epoll's observed set of output-fds
        self._wants_flag(do_send, EPOLLOUT)

    def _wants_flag(self, wants_flag, flag):
        if wants_flag:
            epoll_flags = self.epoll_flags | flag
        else:
            epoll_flags = self.epoll_flags & ~flag
        if self.epoll_flags != epoll_flags:
            self.epoll_flags = epoll_flags
            self.epoll.modify(self.fd, epoll_flags)

    def recv_ready(self):
        ## called when wants_recv is True and self.fd has data available
        pass

    def send_ready(self):
        ## called when wants_send is True and self.fd is clear to send
        pass

    def send(self, eth_frame):
        pass

    def refresh(self, tm_now):
        ## called in periodic intervals
        pass

class FrameQueue:
    def __init__(self):
        self.queue = deque()

    def is_empty(self):
        return len(self.queue) == 0

    def append(self, data):
        self.queue.appendleft(data)

    def get_frame(self):
        return self.queue.pop() if len(self.queue) else None

class NetworkBackend:
    def __init__(self, server):
        self.server = server        ## WsnicServer
        self.config = server.config ## WsnicConfig

    def open(self):
        pass

    def close(self):
        pass

    def attach_ws_client(self, ws_client):
        ## called by WebSocketClient.recv() after the WebSocket handshake completed
        pass

    def detach_ws_client(self, ws_client):
        ## called by WebSocketClient.close(), even if attach_ws_client() was never called (must be idempotent)
        pass

    def forward_from_ws_client(self, ws_client, eth_frame):
        ## Called by WebSocketClient.recv() when a new eth_frame has arrived
        pass
