##
## nbe_brveth.py
## Network backend: Network bridge with one veth-pair and an AF_PACKET-Socket per WebSocket client.
##

import os, logging, struct, fcntl, socket

from wsnic import Pollable, NetworkBackend, FrameQueue, Exec, mac2str, log_eth_frame
from wsnic.nbe_brtap import BridgedTapNetworkBackend

logger = logging.getLogger('nbe_brveth')

SIOCSIFADDR    = 0x00008916
SIOCSIFNETMASK = 0x0000891C
SIOCSIFHWADDR  = 0x00008924

ETH_P_ALL = 0x0003

class BridgedVethNetworkBackend(BridgedTapNetworkBackend):
    def __init__(self, server):
        super().__init__(server)

    def forward_from_ws_client(self, ws_client, eth_frame):
        if not ws_client.mac_addr:
            dst_mac, src_mac = struct.unpack_from('6s6s', eth_frame)
            self.set_client_mac(ws_client, src_mac)
            ## ws_client.pkt_sink is an instance of BridgedVethCLient
            logger.info(f'assigning VM MAC {mac2str(src_mac)} to {ws_client.pkt_sink.veth_vm_iface}')
            ws_client.pkt_sink.set_mac_addr(src_mac)
            logger.info(f'{ws_client.addr}: registered MAC address {mac2str(src_mac)}')
        super().forward_from_ws_client(ws_client, eth_frame)

    def dhcp_lease_assigned(self, mac_addr, ip_addr):
        print(f'==> {mac2str(mac_addr)} <-> {ip_addr}')

    def _create_pollable(self, ws_client):
        return BridgedVethCLient(self.server, ws_client)

class BridgedVethCLient(Pollable):
    INSTANCE_COUNTER = 0

    def __init__(self, server, ws_client):
        super().__init__(server)
        self.ws_client = ws_client            ## WebSocketClient, the associated ws_client
        self.out = FrameQueue()               ## frames waiting to be send
        self.br_iface = server.netbe.br_iface ## the bridge's interface name, for example 'wsbr0'
        self.veth_br_iface = None             ## the bridge-side of the veth pair, for example vethbr0
        self.veth_vm_iface = None             ## the vm-side of the veth pair, for example vethvm0
        self.sock = None                      ## our local packet socket

    def set_mac_addr(self, mac_addr):
        pass

    def set_ip_and_netmask(self, ip_addr, netmask):
        vm_iface = self.veth_vm_iface.encode()
        ifreq = struct.pack('16sH2s4s8s', vm_iface, socket.AF_INET, b'\x00'*2, socket.inet_aton(ip_addr), b'\x00'*8)
        fcntl.ioctl(self.fd, SIOCSIFADDR, ifreq)
        ifreq = struct.pack('16sH2s4s8s', vm_iface, socket.AF_INET, b'\x00'*2, socket.inet_aton(netmask), b'\x00'*8) 
        fcntl.ioctl(self.fd, SIOCSIFNETMASK, ifreq)

    def open(self):
        ## generate distinct interface names for the veth pair
        self.veth_br_iface = f'vethbr{BridgedVethCLient.INSTANCE_COUNTER}'
        self.veth_vm_iface = f'vethvm{BridgedVethCLient.INSTANCE_COUNTER}'
        BridgedVethCLient.INSTANCE_COUNTER += 1

        ## create veth pair, attach one side (veth_br_iface) to the bridge
        run = Exec(logger, check=True)
        run(f'ip link add dev {self.veth_br_iface} type veth peer name {self.veth_vm_iface}')
        run(f'ip link set dev {self.veth_br_iface} master {self.br_iface}')
        run(f'ip link set dev {self.veth_br_iface} mtu {self.config.dhcp_mtu}')
        #run(f'ip link set dev {self.veth_br_iface} promisc on')
        run(f'ip link set dev {self.veth_vm_iface} mtu {self.config.dhcp_mtu}')
        #run(f'ip link set dev {self.veth_vm_iface} promisc on')

        ## bring both ends of the veth pair up
        run(f'ip link set dev {self.veth_br_iface} up')
        run(f'ip link set dev {self.veth_vm_iface} up')

        ## open and connect packet socket to veth pair's vm-side
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((self.veth_vm_iface, 0))

        super().open(self.sock.fileno())
        logger.info(f'created veth pair ({self.veth_br_iface}, {self.veth_vm_iface})')

    def close(self):
        super().close()
        if self.sock:
            self.sock.close()
            self.sock = None
            logger.info(f'destroyed veth pair ({self.veth_br_iface}, {self.veth_vm_iface})')
        if self.veth_br_iface:
            Exec(logger, check=True)(f'ip link del {self.veth_br_iface}')

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
            self.sock.send(eth_frame)
            # log_eth_frame('ws->veth', eth_frame, logger)

    def recv_ready(self):
        eth_frame = self.sock.recv(65535)
        self.ws_client.send(eth_frame)
        # log_eth_frame('veth->ws', eth_frame, logger)
