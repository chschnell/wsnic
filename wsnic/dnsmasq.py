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
        dhcp_dns = ','.join(self.config.dhcp_nameserver)
        cmdline = ['dnsmasq', '--keep-in-foreground', '--no-ping', '--no-hosts',
            f'--interface={iface}',
            f'--except-interface=lo',
            f'--listen-address={self.config.server_addr}',
            f'--bind-interfaces',
            f'--dhcp-range={dhcp_ip_lo},{dhcp_ip_hi},{self.config.netmask},{self.config.dhcp_lease_time}s',
            f'--dhcp-option=6,{dhcp_dns}',
            f'--dhcp-sequential-ip',
        ]
        if self.config.dhcp_domain_name:
            cmdline.append(f'--domain={self.config.dhcp_domain_name}')
        if self.config.dhcp_lease_file:
            cmdline.append(f'--dhcp-leasefile={self.config.dhcp_lease_file}')
        else:
            self.lease_file = tempfile.NamedTemporaryFile(delete=False)
            self.lease_file.close()
            cmdline.append(f'--dhcp-leasefile={self.lease_file.name}')

        log_cmdline = ''
        if logger.isEnabledFor(logging.DEBUG):
            log_cmdline = f': {" ".join(cmdline)}'
        logger.info(f'{self.config.server_addr}: starting DHCP/DNS child process dnsmasq{log_cmdline}')
        self.dnsmasq_p = subprocess.Popen(cmdline)

    def close(self):
        if self.dnsmasq_p:
            self.dnsmasq_p.terminate()
            self.dnsmasq_p.wait()
            self.dnsmasq_p = None
            logger.info('child process dnsmasq terminated')
        if self.lease_file:
            os.unlink(self.lease_file.name)
            self.lease_file = None
