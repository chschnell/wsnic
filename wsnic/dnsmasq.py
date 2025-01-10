##
## dnsmasq.py
## dnsmasq DHCP server.
##

import logging, os, shutil, tempfile, subprocess

logger = logging.getLogger('dnsmasq')

class Dnsmasq:
    def __init__(self, server):
        self.server = server
        self.config = server.config
        self.lease_file = None
        self.dnsmasq_p = None

    def open(self, iface):
        if shutil.which('dnsmasq') is None:
            logger.warning(f'dnsmasq: file not found (Debian: install apt package dnsmasq)')
            return
        dhcp_ip_lo = self.config.host_addrs[0]
        dhcp_ip_hi = self.config.host_addrs[-1]
        dhcp_dns = ','.join(self.config.dhcp_domain_name_server)
        # '--no-resolv', '--no-hosts', 
        # --dhcp-relay=<local address>[,<server address>[#<server port>]][,<interface]
        # f'--dhcp-relay=192.168.2.1,10.0.0.1', f'--dhcp-proxy',
        dnsmasq_cmdline = ['dnsmasq', '--keep-in-foreground', '--no-ping',
            f'--interface={iface}',
            f'--except-interface=lo',
            f'--listen-address={self.config.server_addr}',
            f'--bind-interfaces',
            f'--dhcp-range={dhcp_ip_lo},{dhcp_ip_hi},{self.config.netmask},{self.config.dhcp_lease_time}s',
            f'--dhcp-option=6,{dhcp_dns}',
            #f'--dhcp-option=26,{self.config.dhcp_mtu}',
            f'--dhcp-sequential-ip',
        ]
        if self.config.dhcp_domain_name:
            dnsmasq_cmdline.append(f'--domain={self.config.dhcp_domain_name}')
        if self.config.dhcp_lease_file:
            dnsmasq_cmdline.append(f'--dhcp-leasefile={self.config.dhcp_lease_file}')
        else:
            self.lease_file = tempfile.NamedTemporaryFile(delete=False)
            self.lease_file.close()
            dnsmasq_cmdline.append(f'--dhcp-leasefile={self.lease_file.name}')

        logger.info(f'start child process: {" ".join(dnsmasq_cmdline)}')
        self.dnsmasq_p = subprocess.Popen(dnsmasq_cmdline)

    def close(self):
        if self.dnsmasq_p:
            self.dnsmasq_p.terminate()
            self.dnsmasq_p.wait()
            self.dnsmasq_p = None
            logger.info('dnsmasq child process terminated')
        if self.lease_file:
            os.unlink(self.lease_file.name)
            self.lease_file = None
