##
## wsnic - WebSocket to TAP device proxy server
## Shared package classes.
##

from select import EPOLLIN, EPOLLOUT
from collections import deque

def mac2str(mac):
    mac = mac.hex()
    return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])

class Pollable:
    def __init__(self, server, epoll_flags=EPOLLIN):
        self.server = server
        self.config = server.config
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
