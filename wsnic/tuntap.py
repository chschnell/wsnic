##
## tuntap.py
## Linux TUN/TAP virtual network device definitions.
##
## Links:
## - netdevice - low-level access to Linux network devices
##   https://man7.org/linux/man-pages/man7/netdevice.7.html
## - Tun/Tap interface tutorial
##   https://backreference.org/2010/03/26/tuntap-interface-tutorial/index.html
## - if_tun.h - TUN/TAP device ioctl interface
##   https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h
## - ifconfig.py - many useful ioctl() calls
##   https://github.com/rlisagor/pynetlinux/blob/master/pynetlinux/ifconfig.py
## - interfaces.py - more useful ioctl() calls
##   https://gist.github.com/firaxis/0e538c8e5f81eaa55748acc5e679a36e

import os, struct, fcntl

TAP_CLONE_DEV = '/dev/net/tun'
TUNSETIFF     = 0x400454ca
IFF_TAP       = 0x0002
IFF_NO_PI     = 0x1000

def open_tap(tap_ifname, tap_clone_dev=None):
    ## Open or create a TAP device and return the tuple (fd, ifname).
    ##
    ## Arguments
    ## - str tap_ifname
    ##     Either the ifname of an existing TAP device or the pattern for
    ##     auto-generated TAP device ifames, for example "extap%d" which
    ##     generates extap0, extap1, ..., extapN.
    ## - str|None tap_clone_dev
    ##     TAP clone device file path, dynamically created (for example by
    ##     macvtap) or '/dev/net/tun' (which is used by default).
    ##
    ## Return values
    ## - int fd
    ##     The TAP device's open, non-blocking file descriptor.
    ## - str ifname
    ##     Either the same as tap_ifname or the created TAP device's ifname.
    ##
    ## Close fd by using os.close(fd) when it is no longer used. If the TAP
    ## device was created by this function it gets automatically deleted
    ## when fd is closed.
    ##
    ## Use os.read(fd) and os.write(fd) to exchange ethernet frames with the
    ## TAP device.

    tap_fd = os.open(tap_clone_dev if tap_clone_dev else TAP_CLONE_DEV, os.O_RDWR | os.O_NONBLOCK)
    try:
        os.set_blocking(tap_fd, False)
        ifreq = struct.pack('16sH', tap_ifname.encode(), IFF_TAP | IFF_NO_PI)
        tunsetiff_result = fcntl.ioctl(tap_fd, TUNSETIFF, ifreq)
        tap_ifname = tunsetiff_result[:16].rstrip(b'\0').decode()
        return tap_fd, tap_ifname
    except:
        os.close(tap_fd)
        raise
