##
## dnsmasq.py
## dnsmasq DHCP server.
##

import logging, shutil, subprocess

logger = logging.getLogger('dnsmasq')

class DnsmasqDhcpServer:
    def __init__(self, server):
        self.server = server
        self.config = server.config
        self.dnsmasq_p = None

    def open(self, iface):
        if shutil.which('dnsmasq') is None:
            logger.warning(f'dnsmasq: file not found (Debian: install apt package dnsmasq)')
            return
        dhcp_ip_lo = self.config.host_addrs[0]
        dhcp_ip_hi = self.config.host_addrs[-1]
        dns_servers = ','.join(self.config.dhcp_domain_name_server)
        dnsmasq_cmdline = [
            'dnsmasq', '--no-hosts', '--no-resolv', '--keep-in-foreground', '--no-ping',
            f'--interface={iface}', f'--listen-address={self.config.server_addr}', '--bind-interfaces',
            f'--dhcp-range={dhcp_ip_lo},{dhcp_ip_hi},{self.config.netmask},{self.config.dhcp_lease_time}s',
            f'--dhcp-option=6,{dns_servers}' ]
        logger.info(f'run child process: {" ".join(dnsmasq_cmdline)}')
        self.dnsmasq_p = subprocess.Popen(dnsmasq_cmdline)

    def close(self):
        if self.dnsmasq_p:
            self.dnsmasq_p.terminate()
            self.dnsmasq_p.wait()
            self.dnsmasq_p = None
            logger.info('dnsmasq child process terminated')
