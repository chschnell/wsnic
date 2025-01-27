**wsnic** (or WebSocket-NIC) is a layer-2 proxy server that connects WebSocket clients to a shared virtual Linux bridge.
Clients connected to wsnic can communicate with each other like in a physical network, and if enabled can also access external networks and the Internet.

## Overview

There are two different ways to install wsnic, see

* **[Docker installation](#docker-installation)** about installing wsnic with Docker, and
* **[Source installation](#source-installation)** about installing wsnic from this repository.

In either case, see section **[CLI options](#cli-options)** next about wsnic's command line interface for configuration options.

For WebSocket Secure support (wss://) see section **[WebSocket Secure support](#websocket-secure-support)**.

### Features

* exchanges unmodified IEEE 802.3 [ethernet frames](https://en.wikipedia.org/wiki/Ethernet_frame) between a virtual Linux network and any number of WebSocket clients
* creates a single virtual [bridge](https://wiki.archlinux.org/title/Network_bridge) and one [TAP device](https://en.wikipedia.org/wiki/TUN/TAP) per WebSocket client
* supports attaching the bridge to a physical network using NAT masquerading to grant Internet-access to WebSocket guests
* supports WebSocket Secure (`wss://`) connections with [stunnel](https://www.stunnel.org/)
* provides DHCP/DNS services to WebSocket guests with [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html)
* sends periodic PINGs to idle WebSocket clients
* written in Python3 with no external dependencies
* see section [How it works](#how-it-works) for more details

## Docker installation

First, follow the official [Docker installation instructions](https://docs.docker.com/engine/install/debian/) to install the latest Docker release.

Then pull the latest wsnic container from Docker Hub and run it with Internet-access for clients enabled (by the **`-i`** command line option) using:

```bash
docker run --rm --interactive --tty \
    --cap-add=NET_ADMIN \
    --device /dev/net/tun:/dev/net/tun \
    -p 8086:8086 \
    chschnell86/wsnic:latest -i
```

To instead run wsnic with WebSocket Secure (wss://) support use:

```bash
docker run --rm --interactive --tty \
    --cap-add=NET_ADMIN \
    --device /dev/net/tun:/dev/net/tun \
    -p 8086:8086 \
    -p 8087:8087 \
    -v ~/cert/cert.crt:/opt/wsnic/cert/cert.crt \
    -v ~/cert/cert.key:/opt/wsnic/cert/cert.key \
    chschnell86/wsnic:latest -i
```

Brief description for each of these Docker command line arguments, and why they're needed:

* **--cap-add=NET_ADMIN**  
   Allow Docker application to modify internal Docker network, needed to add/remove network bridge and TAP devices.
* **--device /dev/net/tun:/dev/net/tun**  
   Map host's TUN device file into Docker image, this device is needed to create TAP devices and otherwise not available in Docker images.
* **-p 8086:8086**  
   Maps the WebSocket (ws://) port number `<host-port>:<docker-port>` to host port 8086, for example `12345:8086` would instead expose wsnic on the host's port 12345.
* **-p 8087:8087**  
   Maps the WebSocket Secure (wss://) port number to host port 8087, only needed when wss is used.
* **-v ~/cert/cert.crt:/opt/wsnic/cert/cert.crt** (and similar)  
   Maps the WebSocket Secure certificate file to `~/cert/cert.crt`.  
   In order to pass files (`wsnic.conf`, `cert.crt` or `cert.key`) from the host into the Docker image they need to be volume mounted using Docker command line option `-v`. When running under Docker, upon startup wsnic checks for specific files at these fixed paths:
  * **`/opt/wsnic/wsnic.conf`** for the wsnic configuration file
  * **`/opt/wsnic/cert/cert.crt`** for the WebSocket Secure server certificate file
  * **`/opt/wsnic/cert/cert.key`** for the WebSocket Secure private key file

For further information, see sections:

* **[CLI options](#cli-options)** about wsnic's command line interface (or use `-h`)
* **[WebSocket Secure support](#websocket-secure-support)** about WebSocket Secure support (wss://)

> [!TIP]
> To build the Docker container locally, clone this repository and build it with (for example) tag name `wsnic:local` using:
>
> ```bash
> git clone https://github.com/chschnell/wsnic.git
> cd wsnic
>
> docker buildx build -t wsnic:local .
> ```
>
> The Docker command line to run it is the same as described above, just replace `chschnell86/wsnic:latest` with `wsnic:local`.

## CLI options

wsnic supports configuration through its Command Line Interface (**CLI**) and optionally by using a configuration file. Each setting in the configuration file has the same effect as a CLI option with a similar name, for example, CLI option `--foo-bar` has the same effect as configuration file setting `foo_bar`. Options specified on the command line take precedence over those in `wsnic.conf`.

> [!TIP]
> Copy template file [`wsnic.conf.template`](./wsnic.conf.template) to `wsnic.conf` for a quick-start if you want to use a configuration file.

**Command line interface**

```
usage: wsnic [-h] [-v] [-q] [-c CFGFILE] [-a ADDR] [--ws-port PORT]
             [--wss-port PORT] [-r CRTFILE] [-k KEYFILE] [-s SUBNET]
             [-i] [-f IFACE] [--disable-dhcp] [--dhcp-lease-file DBFILE]
             [-t SECONDS] [-n NAME] [-d IPLIST]

WebSocket to virtual network device proxy server.

options:
    -h, --help
          show this help message and exit
    -v    Output verbose log messages.
    -q    Output warning and error log messages only.
    -c CFGFILE
          Use configuration file CFGFILE, default: wsnic.conf (if
          exists).
    -a ADDR, --ws-address ADDR
          WebSocket server address.
          Use 127.0.0.1 if wsnic runs on the same machine as the
          WebSocket client (browser), or 0.0.0.0 to make wsnic
          available in the network.
          Default: 0.0.0.0 under Docker or 127.0.0.1.
    --ws-port PORT
          WebSocket server port (ws://), default: 8086.
    --wss-port PORT
          WebSocket Secure server port (wss://), default: 8087.
    -r CRTFILE, --wss-certificate CRTFILE
          Absolute path of a PEM formatted file containing either just
          the public server certificate or an entire certificate chain
          including public key, private key, and root certificates.
          Optional, default: "cert/cert.crt" (if exists).
    -k KEYFILE, --wss-private-key KEYFILE
          Absolute path of a PEM formatted file containing only the
          private key of the server certificate.
          Optional, default: "cert/cert.key" (if exists).
    -s SUBNET, --subnet SUBNET
          The wsnic subnet in CIDR notation, default: 192.168.86.0/24.
          The subnet's first and last IP addresses are reserved for
          network and broadcast addresses. The subnet's second IP is
          reserved for the bridge device (also gateway and DHCP server
          IP). The remaining IP addresses are used for the DHCP
          address pool.
          Example for the default subnet:
          - Network address: 192.168.86.0
          - Broadcast address: 192.168.86.255
          - Bridge/gateway/DHCPD address: 192.168.86.1
          - DHCP address pool: 192.168.86.2 ... 192.168.86.254
          The default subnet might conflict with your local network
          configuration and must then be changed accordingly.
    -i, --enable-inet
          Grant bridge access to the host's network (including
          Internet if available) using inet_iface.
    -f IFACE, ---inet-iface IFACE
          Interface name of a physical network device that provides
          access to the Internet (for example "eth0" or "enp0s3").
          wsnic will try to auto-detect this interface, this option is
          only needed to force an interface name in case detection
          fails. This option only takes effect if CLI option -i is
          also present.
          Optional, default (Docker only): "eth0".
    --disable-dhcp
          Disable DHCP/DNS service using dnsmasq.
    --dhcp-lease-file DBFILE
          DHCP lease database file path, default: undefined.
          If undefined, wsnic uses a temporary file which will be
          deleted on close.
    -t SECONDS, ---dhcp-lease-time SECONDS
          DHCP lease time in seconds, default: 86400 (24 hours).
    -n NAME, ---dhcp-domain-name NAME
          Domain Name of this subnet published in DHCP replies.
          Optional, default: undefined.
    -d IPLIST, --dhcp-nameserver IPLIST
          Comma-separated list of Domain Name Server (DNS) IP
          address(es) published in DHCP replies, for example:
              "8.8.8.8, 8.8.4.4"
          If undefined, the bridge's IP address is used as the DNS
          address (which gets handled by dnsmasq).
          Optional, default: undefined.
```

## WebSocket Secure support

WebSocket Secure (`wss://`) support is optional and enabled by passing a TLS server certificate file to wsnic (either by CLI option or in `wsnic.conf`), which means you need:

1. a DNS record for the hostname of your wsnic server
2. a TLS server certificate issued for that DNS hostname

If your wsnic server has a public DNS record for its hostname you should use a service like [Let’s Encrypt](https://letsencrypt.org/) to get a TLS certificate for it, otherwise you can create your own self-signed certificate as described in the next section.

### Self-signed TLS server certificate

Setting up a self-signed certificate involves two steps, after generating it you also have to configure your browser to accept it.

> [!NOTE]
> The following instructions use **`localhost`** as the DNS hostname and **`/host/path`** as the directory where TLS certificate files are stored on the wsnic host, you need to replace both consistently according to your setup and network environment.

> [!TIP]
> Make sure to use the same **hostname** for the DNS hostname in the server certificate, in browser URLs and in HTTP server's virtual host definitions. For example, if you plan to run the server on the same machine as your browser, use `localhost` in all cases.

#### Step 1/2: Generate a self-signed certificate

To issue a basic self-signed TLS server certificate for DNS hostname `localhost`:

```bash
mkdir /host/path
cd /host/path

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cert.key -out cert.crt -subj "/CN=localhost"
```

#### Step 2/2: Setup browser to accept the self-signed certificate

By default, modern browsers refuse to connect to HTTPS (and WebSocket Secure) servers that present a self-signed certificate. In order to get around that you have to manually grant permission in your browser.

> [!NOTE]
> These instructions are for Mozilla Firefox. If you want to use **Google Chrome**, start `chrome` with command line options `--disable-web-security --ignore-certificate-errors --allow-running-insecure-content --user-data-dir=/tmp/chrome-temp`, and replace `/tmp/chrome-temp` with some directory for the session data.

Start wsnic and direct your browser to your wsnic server using a HTTPS URL like:

```
https://localhost:8087
```

You will get a security warning that you need to acknowledge once to grant permission permanently. After that you should see a reply page from wsnic's WebSocket server that reads:

```
Failed to open a WebSocket connection: invalid Connection header: keep-alive.

You cannot access a WebSocket server directly with a browser. You need a WebSocket client.
```

This seeming error message is in fact our expected success message here, if you see it then things are working as they should and you can close the browser tab.

## Source installation

To use wsnic without Docker you can execute wsnic directly from its source code as described below. Instructions are tested with Debian 12 (Bookworm) netinst (without Desktop).

> [!WARNING]
> Unlike the Docker image this installation method will run directly on the
> host, meaning it is **not isolated** from the host as is the case with Docker.
> It is recommended to use this installation method only in a **virtual machine**
> dedicated for this purpose in order to avoid unwanted system modifications in
> case of a crash.
>
> Having said that, wsnic attempts to restore all system state back as it was
> before starting, for example the host's network configuration and settings.

> [!NOTE]
> `stunnel` is only required for `wss://` support and otherwise not needed.

First, make sure that the packages required by wsnic are installed:

```bash
sudo apt install python3-venv iproute2 iptables dnsmasq stunnel
```

Stop and disable the systemd dnsmasq service with (if you want to run it, make sure that it does not bind to newly created network devices):

```bash
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq
```

Next, clone a working copy of this repository:

```bash
git clone https://github.com/chschnell/wsnic.git
```

Finally, run wsnic using:

```bash
cd wsnic
sudo ./wsnic.sh [WSNIC-OPTIONS]
```

See section **[CLI options](#cli-options)** for documentation on `WSNIC-OPTIONS` (or use `-h`).

## Troubleshooting

### sysctl

The necessity for adjusting [`sysctl`](https://linux.die.net/man/8/sysctl) settings in the Linux host is not entirely clear, and the host's defaults of some `sysctl` settings are also not always known. For this reason wsnic does not modify these settings by itself, they can be changed from outside wsnic as described below.

**sysctl (non-Docker)**

To see relevant sysctl settings use:

```bash
sudo sysctl -a | grep forward
```

Look for `net.ipv4.ip_forward` and make sure it is set to `1`, otherwise change it using:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

For some sysctl settings it is unclear whether they're even relevant, if there are still issues you might try:

```bash
sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv4.conf.default.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.default.forwarding=1
```

**sysctl (Docker)**

To change sysctl settings from within the Docker image would require to run it with the [`--privileged`](https://docs.docker.com/reference/cli/docker/container/run/#privileged) flag which is otherwise not needed by wsnic and hence avoided.

Pass sysctl settings on the `docker run` command line like so:

```bash
docker run ... \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv4.conf.all.forwarding=1 \
    --sysctl net.ipv4.conf.default.forwarding=1 \
    --sysctl net.ipv6.conf.all.forwarding=1 \
    --sysctl net.ipv6.conf.default.forwarding=1 ...
```

## How it works

Overview of wsnic and its network components:

```
 +-----+     +-----+         +-----+
 | ws0 |     | ws1 |   ...   | wsN |    (WebSocket clients)
 +--+--+     +--+--+         +--+--+
    |           |               |
+===+===========+===============+====+
|   :           :               :    |  (wsnic proxy server)
+===+===========+===============+====+
    |           |               |
+---+----+  +---+----+      +---+----+
| wstap0 |  | wstap1 |      | wstapN |  (TAP devices)
+---+----+  +---+----+      +---+----+
    |           |               |
+---+-----------+---------------+----+
|               wsbr0                |  (virtual bridge)
+-----------------+-------------+----+
                  |             |
          NAT (MASQUERADE)      |
                  |         [dnsmasq]   (DHCP server)
               +--+---+
               | eth0 |                 (physical network)
               +--+---+
                  |
               Internet
```

Roughly, wsnic works like this:

* Upon startup, wsnic:
  * creates virtual bridge `wsbr0` and assigns it the subnet's first available IP address,
  * optionally attaches `wsbr0` to a physical network adapter named (for instance) `eth0` using NAT,
  * optionally starts DHCP server `dnsmasq` and binds it to the IP address of `wsbr0`, and
  * starts operating as the WebSocket server, listening for WebSocket client connections
* After completing the handshake with a newly accepted WebSocket client connection `wsX`, wsnic:
  * creates a TAP device `wstapX`,
  * connects `wstapX` to `wsbr0`, and
  * begins passing ethernet frames between `wsX` and `wstapX`
* If a WebSocket client disconnects, wsnic removes the associated TAP device from the bridge (and network)
* DHCP server `dnsmasq` assigns DHCP leases to WebSocket clients, it is also the default DNS server

wsnic avoids allocating and copying internal buffers by maintaining a buffer pool and using vectored I/O where possible ([`socket.sendmsg()`](https://docs.python.org/3/library/socket.html#socket.socket.sendmsg) and [`os.writev()`](https://docs.python.org/3/library/os.html#os.writev) for gathering `write`, multiple attempts to implement scattering `read` for TAP devices have so far failed, see also [TODO](#todo)).

## TODO

### Scattering read from TAP device

WebSocket clients typically send few and receive many packets, which makes the read performance of the TAP device a possible I/O bottleneck in wsnic.

What is needed is some function that reads multiple different-sized packets from a TAP device (as a file or socket) into a set of preallocated buffers at once, non-blocking and returning complete packets only. Only as many packets as are currently available should be returned, possibly zero.

The problem is that the only suitable function in Linux for scattering read of packets with varying sizes seems to be [`recvmmsg()`](https://man7.org/linux/man-pages/man2/recvmmsg.2.html) which needs a socket file descriptor.

Yet various attempts to create a proper socket for the TAP device failed so far (tried `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)` and `socket(AF_PACKET, SOCK_RAW)` with and without `ETH_P_ALL`, `setsockopt(SOL_SOCKET, SO_BINDTODEVICE, <0-terminated-bytes-string>)`. Opening the socket and various tested `ioctl()` calls work, but sending and/or receiving fails.

So all that is given is the regular, non-socket TAP file descriptor returned by [`os.open()`](https://docs.python.org/3/library/os.html#os.open) which is incompatible with `recvmmsg()`, all that can be done is to read TAP packets one by one using [`os.readv()`](https://docs.python.org/3/library/os.html#os.readv) with a single (preallocated) packet buffer per call. Any help/ideas here would be greatly appreciated!.

### io_uring

[io_uring](https://unixism.net/loti/what_is_io_uring.html) looks like an efficient approach for vectored I/O for both socket and TAP file descriptors, there are Python examples on the web and there's at least one Python wrapper library [Liburing](https://github.com/YoSTEALTH/Liburing).

## Credits

* [v86](https://github.com/copy/v86), the browser-based x86 emulator which wsnic was developed for.
* [websockproxy](https://github.com/benjamincburns/websockproxy), the project that inspired wsnic.
