##
## wsnic - WebSocket to TAP device proxy server
## Shared package classes.
##

import logging, random, subprocess, struct

from select import EPOLLIN, EPOLLOUT
from collections import deque

def run(cmd_line, logger, check=False):
    if logger.isEnabledFor(logging.INFO):
        logger.info(f'run: {" ".join(cmd_line)}')
    subprocess.run(cmd_line, check=check)

def mac2str(mac):
    mac = mac.hex()
    return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])

def random_private_mac():
    ## Private MAC addresses can be identified by having the
    ## second-least-significant bit of the most significant byte set. And
    ## as unicast addresses, they must not have the least significant bit
    ## set. That means any addres matching any pattern below is private:
    ##   x2:xx:xx:xx:xx:xx
    ##   x6:xx:xx:xx:xx:xx
    ##   xA:xx:xx:xx:xx:xx
    ##   xE:xx:xx:xx:xx:xx
    ## Source:
    ##   https://www.blackmanticore.com/fc5c95c7c2e29e262ec89c539852f8fb
    ##   https://superuser.com/a/907834
    mac_addr = bytearray(random.randbytes(6))
    mac_addr[0] = (mac_addr[0] & ~0x01) | 0x02
    return mac_addr

ETH_TYPES = {
    0x0800: 'IPv4',
    0x86DD: 'IPv6',
    0x0806: 'ARP',
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
    eth_type = ETH_TYPES.get(eth_type, None)
    if eth_type is None:
        eth_type = hex(eth_type)
    ip_proto = IP_PROTOS.get(ip_proto, ip_proto)
    logger.info(f'{tag} {mac2str(src_mac)}->{mac2str(dst_mac)} eth_type={eth_type} ip_proto={ip_proto} len={len(eth_frame)}')

class Pollable:
    def __init__(self, server, epoll_flags=EPOLLIN):
        self.server = server
        self.config = server.config
        self.netbe = server.netbe
        self.epoll = server.epoll
        self.epoll_flags = epoll_flags
        self.fd = None

    def wants_recv(self, do_recv):
        self._wants_flag(do_recv, EPOLLIN)

    def wants_send(self, do_send):
        self._wants_flag(do_send, EPOLLOUT)

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

    def send(self, eth_frame):
        pass

    def refresh(self, tm_now):
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
        self.ws_clients = set()     ## set(WebSocketClient ws_client)
        self.mac_to_client = {}     ## dict(bytes mac[6] => WebSocketClient ws_client)

    def attach_client(self, ws_client):
        self.ws_clients.add(ws_client)

    def detach_client(self, ws_client):
        if ws_client.mac_addr and ws_client.mac_addr in self.mac_to_client:
            del self.mac_to_client[ws_client.mac_addr]
        self.ws_clients.discard(ws_client)

    def set_client_mac(self, ws_client, mac):
        if ws_client.mac_addr != mac:
            if ws_client.mac_addr and ws_client.mac_addr in self.mac_to_client:
                del self.mac_to_client[ws_client.mac_addr]
            self.mac_to_client[mac] = ws_client
            ws_client.mac_addr = mac

    def open(self):
        pass

    def close(self):
        pass

    def forward_from_ws_client(self, ws_client, eth_frame):
        ## Called by WebSocketClient.recv() when a new eth_frame has arrived.
        pass

    def dhcp_lease_assigned(self, mac_addr, ip_addr):
        ## Called by DhcpNetwork.assign_address() whenever a DHCP lease has been assigned to a MAC address.
        pass
