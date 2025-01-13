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
        if not os.path.isfile(self.config.wss_certificate):
            logger.warning(f'{self.config.wss_certificate}: file not found, TLS support disabled')
            return
        elif shutil.which('stunnel') is None:
            logger.warning(f'stunnel: file not found, TLS support disabled (Debian: install apt package stunnel)')
            return

        ## build stunnel.conf
        if self.config.is_docker_env:
            stunnel_foreground = 'quiet'
            stunnel_debug = 'crit'
        else:
            stunnel_foreground = 'yes' if logger.isEnabledFor(logging.DEBUG) else 'quiet'
            stunnel_debug = 'err'
        stunnel_conf = [
            f'foreground = {stunnel_foreground}',
            f'debug = {stunnel_debug}',
            f'',
            f'[wsnic]',
            f'TIMEOUTclose = 0',
            f'socket = l:TCP_NODELAY=1',
            f'accept = {self.config.ws_address}:{self.config.wss_port}',
            f'connect = {self.config.ws_port}',
            f'cert = {self.config.wss_certificate}'
        ]
        if self.config.wss_private_key:
            stunnel_conf.append(f'key = {self.config.wss_private_key}')

        stunnel_conf_txt = '\n'.join(stunnel_conf)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f'stunnel.conf [{self.stunnel_conf.name}]:' + '\n' + stunnel_conf_txt)

        ## write stunnel.conf to temp file
        self.stunnel_conf = tempfile.NamedTemporaryFile(delete=False)
        self.stunnel_conf.write(stunnel_conf_txt.encode() + b'\n')
        self.stunnel_conf.close()

        ## execute stunnel
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
