##
## wsnic - WebSocket to TAP device proxy server
## Shared package classes.
##

import os, logging, random, subprocess, struct, collections

from select import EPOLLIN, EPOLLOUT

## Ethernet frames usually do net exceed 1514 bytes in length (14 bytes
## header + 1500 data), jumbo frames however go up to 9014 bytes.
## Payloads that exceed MAX_PAYLOAD_SIZE are dropped by wsnic.
##
MAX_PAYLOAD_SIZE = 16384

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

def log_eth_frame(tag, frame_buf, logger):
    dst_mac, src_mac, eth_type, ip_proto = struct.unpack_from('!6s6sH9xB10x', frame_buf)
    eth_type = ETH_TYPES.get(eth_type, hex(eth_type))
    ip_proto = IP_PROTOS.get(ip_proto, ip_proto)
    logger.info(f'{tag} {mac2str(src_mac)}->{mac2str(dst_mac)} eth_type={eth_type} ip_proto={ip_proto} len={len(frame_buf)}')

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

class BufferPool:
    ## A dynamically growing pool of fixed size bytearray buffers.
    ##
    ## Buffers taken from the pool by get_buffer() must be explicitly
    ## returned to the pool by using one of the put_buffer(s) methods.
    ##
    ## As a convention, any scalar variable that might be assigned a buffer
    ## originating from the pool, or any container that might contain such
    ## a buffer should have the suffix "_pbuf" appended.
    ##
    class pooled_bytearray(bytearray):
        pass

    def __init__(self, buffer_size=MAX_PAYLOAD_SIZE, preallocate=32, max_extend=64):
        self.buffer_size = buffer_size
        self.n_allocated = preallocate
        self.max_extend = max_extend
        self.unused_pool = collections.deque([self.pooled_bytearray(self.buffer_size) for i in range(preallocate)])
        self.n_used_max = 0
        self.n_used = 0

    def get_buffer(self):
        self.n_used += 1
        if self.n_used > self.n_used_max:
            self.n_used_max = self.n_used
        try:
            return self.unused_pool.pop()
        except IndexError:
            n_extend = min(self.n_allocated >> 1, self.max_extend)
            self.unused_pool.extend([self.pooled_bytearray(self.buffer_size) for i in range(n_extend - 1)])
            self.n_allocated += n_extend
            return self.pooled_bytearray(self.buffer_size)

    def put_buffer(self, byteslike_pbuf):
        if not byteslike_pbuf:
            return
        if isinstance(byteslike_pbuf, memoryview):
            view = byteslike_pbuf
            byteslike_pbuf = view.obj
        else:
            view = None
        if isinstance(byteslike_pbuf, self.pooled_bytearray):
            if view:
                view.release()
            self.unused_pool.appendleft(byteslike_pbuf)
            self.n_used -= 1

    def put_buffers(self, iter_pbuf):
        for byteslike_pbuf in iter_pbuf:
            self.put_buffer(byteslike_pbuf)

    def log_statistics(self, logger):
        if self.n_used == 0:
            logger.info(f'buffer pool usage peaked at {self.n_used_max}/{self.n_allocated} buffers')
        else:
            logger.info(f'buffer pool usage peaked at {self.n_used_max}/{self.n_allocated} buffers '
                f'(usage balance: {self.n_used}, {len(self.unused_pool)} in unused pool)')

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

    def close(self, reason=None):
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

    def send_frame(self, frame_pbuf):
        ## send ethernet frame in frame_pbuf to underlying device
        ## only implemented by WebSocketClient and BridgedTapDevice
        pass

class NetworkBackend:
    def __init__(self, server):
        self.server = server        ## WsnicServer
        self.config = server.config ## WsnicConfig

    def open(self):
        pass

    def close(self):
        pass

    def attach_ws_client(self, ws_client):
        ## called by WebSocketClient.handle_ws_handshake() after the WebSocket handshake completed
        pass

    def detach_ws_client(self, ws_client):
        ## called by WebSocketClient.close(), even if attach_ws_client() was never called
        pass

    def forward_from_ws_client(self, ws_client, frame_pbuf):
        ## called by WebSocketClient.handle_ws_message() when a new frame_pbuf has arrived
        pass
