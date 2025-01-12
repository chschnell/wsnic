##
## stunnel.py
## TLS termination proxy server using stunnel.
##

import logging, os, shutil, tempfile, subprocess

logger = logging.getLogger('stunnel')

class StunnelProxyServer:
    def __init__(self, config):
        self.config = config
        self.stunnel_conf = None
        self.stunnel_p = None

    def open(self):
        if not os.path.isfile(self.config.wss_server_cert):
            logger.warning(f'{self.config.wss_server_cert}: file not found, TLS support disabled')
            return
        elif shutil.which('stunnel') is None:
            logger.warning(f'stunnel: file not found, TLS support disabled (Debian: install apt package stunnel)')
            return

        stunnel_foreground = 'yes' if logger.isEnabledFor(logging.DEBUG) else 'quiet'
        stunnel_conf = [
            f'foreground = {stunnel_foreground}',
            f'debug = err',
            f'',
            f'[wsnic]',
            f'TIMEOUTclose = 0',
            f'socket = l:TCP_NODELAY=1',
            f'accept = {self.config.ws_server_addr}:{self.config.wss_server_port}',
            f'connect = {self.config.ws_server_port}',
            f'cert = {self.config.wss_server_cert}'
        ]
        if self.config.wss_server_key:
            stunnel_conf.append(f'key = {self.config.wss_server_key}')

        stunnel_conf_txt = '\n'.join(stunnel_conf)

        self.stunnel_conf = tempfile.NamedTemporaryFile(delete=False)
        self.stunnel_conf.write(stunnel_conf_txt.encode() + b'\n')
        self.stunnel_conf.close()

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f'stunnel.conf [{self.stunnel_conf.name}]:' + '\n' + stunnel_conf_txt)

        stunnel_cmdline = ['stunnel', self.stunnel_conf.name]
        logger.info(f'start child process: {" ".join(stunnel_cmdline)}')
        self.stunnel_p = subprocess.Popen(stunnel_cmdline)

    def close(self):
        if self.stunnel_p:
            self.stunnel_p.terminate()
            self.stunnel_p.wait()
            self.stunnel_p = None
            logger.info('stunnel child process terminated')
        if self.stunnel_conf:
            os.unlink(self.stunnel_conf.name)
            self.stunnel_conf = None
