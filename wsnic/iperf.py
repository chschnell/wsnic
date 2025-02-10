##
## iperf.py
## iperf server.
##

import logging, shutil, subprocess

logger = logging.getLogger('iperf')

class IperfServer:
    def __init__(self, server):
        self.server = server
        self.config = server.config
        self.iperf_p = None

    def open(self):
        if shutil.which('iperf') is None:
            logger.warning(f'iperf: file not found (Debian: install apt package iperf)')
            return
        cmdline = ['iperf', '-s', '-B', self.config.server_addr, '-f', 'm']

        log_cmdline = ''
        p_stdout = None
        p_stderr = None
        if logger.isEnabledFor(logging.DEBUG):
            log_cmdline = f': {" ".join(cmdline)}'
        else:
            p_stdout = subprocess.DEVNULL
            p_stderr = subprocess.STDOUT
        logger.info(f'{self.config.server_addr}: starting iperf child process iperf{log_cmdline}')
        self.iperf_p = subprocess.Popen(cmdline, stdout=p_stdout, stderr=p_stderr)

    def close(self):
        if self.iperf_p:
            self.iperf_p.terminate()
            self.iperf_p.wait()
            self.iperf_p = None
            logger.info('child process iperf terminated')
