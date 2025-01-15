**wsnic** is a WebSocket to virtual network proxy server for Linux.

## Overview

There are two different ways to install wsnic, see

* **[Docker installation](#docker-installation)** about installing wsnic with Docker, and
* **[Source installation](#source-installation)** about installing wsnic from this repository.

In either case, see section **[CLI options](#cli-options)** next about wsnic's command line interface for configuration options.

For WebSocket Secure support (wss://) see section **[WebSocket Secure support](#websocket-secure-support)**.

### Features

* passes IEEE 802.3 [ethernet frames](https://en.wikipedia.org/wiki/Ethernet_frame) between a Linux network and an open number of WebSocket clients
* creates a single [bridge](https://wiki.archlinux.org/title/Network_bridge) and one [TAP device](https://en.wikipedia.org/wiki/TUN/TAP) per WebSocket client
* supports attaching the bridge to a physical network device using Network Address Translation (NAT) to grant Internet-access to WebSocket guests
* uses the [sans-io WebSocket](https://websockets.readthedocs.io/en/stable/reference/sansio/server.html) server protocol implementation from [websockets](https://websockets.readthedocs.io/en/stable/)
* supports WebSocket Secure (`wss://`) connections by offloading to [stunnel](https://www.stunnel.org/)
* uses [`dnsmasq`](https://thekelleys.org.uk/dnsmasq/doc.html) to provide DHCP and DNS services to WebSocket guests
* uses a single-threaded [epoll](https://docs.python.org/3/library/select.html#edge-and-level-trigger-polling-epoll-objects)-loop for all sockets and network devices
* sends periodic PINGs to idle WebSocket clients
* see section [How it works](#how-it-works) for more details

## Docker installation

First, follow the official [Docker installation instructions](https://docs.docker.com/engine/install/debian/) to install the latest Docker release.

Next, either install the Docker container from Docker Hub or build it yourself.

### Install from Docker Hub

Pull the wsnic Docker container from Docker Hub using:

```bash
docker pull chschnell86/wsnic:latest
```

### Build Docker container

Clone this repository and build wsnic Docker container with example tag `wsnic:local` using:

```bash
git clone https://github.com/chschnell/wsnic.git
cd wsnic

docker buildx build -t wsnic:local .
```

### How to use the Docker image

wsnic requires the following `docker run` command line arguments to be present (replace `chschnell86/wsnic:latest` with `wsnic:local` when using a self-build container):

```bash
docker run \
    --cap-add=NET_ADMIN \
    --device /dev/net/tun:/dev/net/tun \
    -p 8086:8086 \
    -p 8087:8087 \
    chschnell86/wsnic:latest [WSNIC-OPTIONS]
```

Brief description for each of these arguments, and why they're needed:

* **--cap-add=NET_ADMIN**  
   Allow Docker application to modify internal Docker network, needed to add/remove network bridge and TAP devices.
* **--device /dev/net/tun:/dev/net/tun**  
   Map host's TUN device file into Docker image, this device is needed to create TAP devices and otherwise not available in Docker images.
* **-p 8086:8086**  
   Maps the WebSocket (ws://) port number `<host-port>:<docker-port>` to host port 8086, for example `12345:8086` would instead expose wsnic on the host's port 12345.
* **-p 8087:8087**  
   Maps the WebSocket Secure (wss://) port number to host port 8087, only needed when wss is used.

In order to pass files (`cert.crt`, `cert.key` or `wsnic.conf`) from the host into the Docker image they need to be volume mounted using Docker command line option `-v`. At startup, wsnic checks for these files at fixed paths:

* `/opt/wsnic/wsnic.conf` for the wsnic configuration file
* `/opt/wsnic/cert/cert.crt` for the server certificate file
* `/opt/wsnic/cert/cert.key` for the private key file

Full example (replace `/host/path` with the absolute file path in your local environment, and if using a self-build container `chschnell86/wsnic:latest` with `wsnic:local`):

```bash
docker run -rm --interactive --tty \
    --cap-add=NET_ADMIN \
    --device /dev/net/tun:/dev/net/tun \
    -p 8086:8086 \
    -p 8087:8087 \
    -v /host/path/cert.crt:/opt/wsnic/cert/cert.crt \
    -v /host/path/cert.key:/opt/wsnic/cert/cert.key \
    chschnell86/wsnic:latest [WSNIC-OPTIONS]
```

Next see section **[CLI options](#cli-options)** for documentation on `WSNIC-OPTIONS` (or use `-h`).

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

First, make sure that the packages required by wsnic are installed:

```bash
sudo apt install python3-venv iproute2 iptables dnsmasq stunnel
```

Stop and disable the systemd dnsmasq service with (if you want to run it, make sure that it does not bind to newly created network devices):

```bash
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq
```

NOTE: `stunnel` is only required for `wss://` support and otherwise not needed.

Next, clone a working copy of this repository and install `websockets` into it using `pip`:

```bash
git clone https://github.com/chschnell/wsnic.git

cd wsnic
python3 -m venv venv
venv/bin/pip3 install websockets
cd ..
```

Finally, run wsnic using:

```bash
sudo ./wsnic.sh [WSNIC-OPTIONS]
```

Next see section **[CLI options](#cli-options)** for documentation on `WSNIC-OPTIONS` (or use `-h`).

## CLI options

wsnic supports configuration through its command line interface (CLI) and optionally by using a configuration file. Each setting in the configuration file corresponds to a CLI option (for example, CLI option `--foo-bar` corresponds to config setting `foo_bar`). Copy template file [`wsnic.conf.template`](./wsnic.conf.template) to `wsnic.conf` for a quick-start if you want to use a configuration file.

Options specified on the command line take precedence over those specified in `wsnic.conf`.

Command line interface of wsnic:

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
          fails.This option only takes effect if CLI option -i is also
          present.
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

WebSocket Secure (`wss://`) support is optional and only enabled if a TLS server certificate is defined (either by CLI option or in `wsnic.conf`), which means you need:

1. a DNS record for the hostname of your wsnic server
2. a TLS server certificate issued for that DNS hostname

If your wsnic server has a public DNS record for its hostname you should use a service like [Let’s Encrypt](https://letsencrypt.org/) to get a TLS certificate for it, otherwise you can create your own self-signed certificate as described in the next section.

The following instructions use **`wsnic.example.com`** as the DNS hostname and **`/host/path`** as the directory where TLS certificate files are stored, you need to replace both consistently according to your setup and network environment.

WebSocket Secure URLs are of the form `wss://wsnic.example.com:8087`.

### Self-signed TLS server certificate

The DNS hostname doesn't need to be fully qualified in private networks, it might also be just `localhost` if wsnic (WebSocket server) and browser (WebSocket client) are running on the same machine.

Setting up a self-signed certificate involves two steps, after generating it you also have to configure your browser to accept it.

#### Step 1/2: Generate a self-signed certificate

To issue a basic self-signed TLS server certificate for DNS hostname `wsnic.example.com`:

```bash
mkdir /host/path
cd /host/path

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cert.key -out cert.crt -subj "/CN=wsnic.example.com"
```

You can also issue the certificate for additional DNS names and/or IP addresses, here an example that adds DNS hostname `wsnic2.example.com` and IP address `12.34.56.78`:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cert.key -out cert.crt -subj "/CN=wsnic.example.com" \
  -addext "subjectAltName=DNS:wsnic2.example.com,IP:12.34.56.78"
```

You can add multiple alternate DNS names and IP addresses, use comma `,` to separate them.

#### Step 2/2: Setup browser to accept the self-signed certificate

By default, modern browsers refuse to connect to HTTPS and WebSocket servers with self-signed TLS certificates. In order to get around that you have to grant permission in your browser. Start wsnic and point your browser at your wsnic server using a HTTPS URL like:

```
https://wsnic.example.com:8087
```

You will get a security warning that you need to acknowledge once to grant permission permanently. After that you should see a reply page from wsnic's WebSocket server that reads:

```
Failed to open a WebSocket connection: invalid Connection header: keep-alive.

You cannot access a WebSocket server directly with a browser. You need a WebSocket client.
```

This seeming error message is in fact our expected success message here, if you see it then things are working as they should and you can close the browser tab.

## Troubleshooting

### sysctl

The necessity for adjusting [`sysctl`](https://linux.die.net/man/8/sysctl) settings in the Linux host is not entirely clear, and the host's defaults of some `sysctl` settings are also not always known. For this reason wsnic does not modify these settings by itself, they can be changed from outside wsnic as described below.

#### sysctl (non-Docker)

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

#### sysctl (Docker)

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

* On startup, wsnic:
  * creates virtual bridge `wsbr0` and assigns it the subnet's first IP address,
  * optionally attaches `wsbr0` to the physical network adapter `eth0` using NAT,
  * optionally starts DHCP server `dnsmasq` and binds it to the IP address of `wsbr0`, and
  * starts operating as the WebSocket server, listening for WebSocket client connections
* After completing the handshake of a newly accepted WebSocket client connection `wsX`, wsnic:
  * creates a TAP device `wstapX`,
  * connects `wstapX` to `wsbr0`, and
  * begins passing ethernet frames between `wsX` and `wstapX`
* If a WebSocket client disconnects, wsnic removes the associated TAP device from the bridge (and network)
* DHCP server `dnsmasq` assigns DHCP leases to WebSocket clients, it is also the default DNS server

## Credits

* [v86](https://github.com/copy/v86), the browser-based x86 emulator wsnic was developed for.
* [websockproxy](https://github.com/benjamincburns/websockproxy), the project that inspired wsnic.
