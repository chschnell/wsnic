**wsnic** is a WebSocket to virtual network proxy server for Linux.

* passes IEEE 802.3 [ethernet frames](https://en.wikipedia.org/wiki/Ethernet_frame) between a Linux network and an open number of WebSocket clients
* creates a single [bridge](https://wiki.archlinux.org/title/Network_bridge) and one [TAP device](https://en.wikipedia.org/wiki/TUN/TAP) per WebSocket client
* supports attaching the bridge to a physical network device using Network Address Translation (NAT) to grant Internet-access to WebSocket clients
* uses the [sans-io WebSocket](https://websockets.readthedocs.io/en/stable/reference/sansio/server.html) server protocol implementation from [websockets](https://websockets.readthedocs.io/en/stable/)
* supports WebSockets Secure (`wss://`) connections by offloading to [stunnel](https://www.stunnel.org/)
* uses [`dnsmasq`](https://thekelleys.org.uk/dnsmasq/doc.html) to provide DHCP and DNS services to WebSocket clients
* uses a single-threaded [epoll](https://docs.python.org/3/library/select.html#edge-and-level-trigger-polling-epoll-objects)-loop for all sockets and network devices
* sends periodic PINGs to idle WebSocket clients

## Building and using the wsnic Docker image

### How to build the wsnic Docker container

Follow the [Docker build instructions](https://docs.docker.com/engine/install/debian/) to install the latest Docker release.

Build Docker container with tag `wsnic:latest` using:

```bash
sudo docker buildx build -t wsnic:latest -f docker/Dockerfile .
```

### Using the wsnic Docker image

There are several environment variables, TCP port numbers and files that can be specified on the `docker run` command line for customization.

| Environment variable | Default | Description |
| :---- | :--- | :--- |
| **WSNIC_SUBNET**                  | `192.168.86.0/24` | The subnet that wsnic will use |
| **WSNIC_ENABLE_HOSTNET**          | `0`               | If set to `1`, grant WebSocket guests access to the host's network (and Internet) |
| **WSNIC_ENABLE_DHCP**             | `1`               | If set to `0`, disable DHCP server dnsmasq for WebSocket guests |
| **WSNIC_DHCP_LEASE_TIME**         | `86400`           | DHCP lease time in seconds |
| **WSNIC_DHCP_DOMAIN_NAME**        |                   | An optional local domain name for the subnet |
| **WSNIC_DHCP_DOMAIN_NAME_SERVER** |                   | An optional, comma-separated list of DNS IP addresses, defaults to dnsmasq if undefined |

Internally, the wsnic Docker image listens on TCP port numbers 80 (ws://) and 443 (wss://), these can be overriden simply with the `-p` command line argument.

An optional TLS server certificate file (and its optional key file) must be volume mounted into to the image, at startup wsnic looks for them at these fixed file paths in the Docker file system:

* `/opt/wsnic/cert/cert.crt`
* `/opt/wsnic/cert/cert.key`

TLS support in wsnic is only enabled if a valid TLS certificate has been found.

A full example to illustrate these options:

```bash
sudo docker run --rm --interactive --tty \
    -e WSNIC_ENABLE_HOSTNET=1 \
    -e WSNIC_DHCP_DOMAIN_NAME=v86.local \
    -v /var/local/crt/cert.crt:/opt/wsnic/cert/cert.crt \
    -v /var/local/crt/cert.key:/opt/wsnic/cert/cert.key \
    -p 8086:80 \
    -p 8087:443 \
    --cap-add=NET_ADMIN \
    --device /dev/net/tun:/dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 \
    wsnic:latest
```

Arguments:

* **--rm**  
   remove Docker image when closing
* **--interactive**  
   keep STDIN open
* **--tty**  
   allocate a pseudo-TTY
* **-e WSNIC_ENABLE_HOSTNET=1**  
   set environment variable WSNIC_ENABLE_HOSTNET to `1`
* **-v /var/local/crt/cert.crt:/opt/wsnic/cert/cert.crt**  
   mount file `/var/local/crt/cert.crt` from host file system into Docker image at `/opt/wsnic/cert/cert.crt`
* **-p 8086:80**  
   map internal Docker TCP port 80 to host's TCP port 8086
* **--cap-add=NET_ADMIN**  
   allow Docker application to modify internal Docker network, needed to add/remove network bridge and TAP devices
* **--device /dev/net/tun:/dev/net/tun**  
   map host's TUN device file into Docker image, this device is needed to create TAP devices and otherwise not available in Docker images
* **--sysctl net.ipv4.ip_forward=1**  
   allow IP forwarding in the Docker image

## How to build wsnic from the sources

Instructions below are tested with Debian 12 (Bookworm) netinst (without Desktop).

### Step 1/3: Install required Linux tools

First, make sure that the packages required by wsnic are installed, for Debian:

```bash
sudo apt install python3-venv iproute2 iptables dnsmasq stunnel
```

Stop and disable the systemd dnsmasq service with (if you want to run it, make sure that it does not bind to newly created network devices):

```bash
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq
```

stunnel is only required for `wss://` support and otherwise not needed.

### Step 2/3: Clone and initialize this repository

Clone a working copy of this repository. Then, install `websockets` into the working copy using `pip`:

```bash
git clone https://github.com/chschnell/wsnic.git

cd wsnic
python3 -m venv venv
venv/bin/pip3 install websockets
cd ..
```

### Step 3/3: Installation setup

Copy [`wsnic.conf.template`](./wsnic.conf.template) to `wsnic.conf` and edit as needed, settings to consider:

* `subnet`, the IP subnet that wsnic will use, it defaults to `192.168.86.0/24` which might conflict with your local network configuration and must then be changed accordingly
* `inet_iface`, set this to the name of a physical network device that can route internet traffic (usually similar to `eth0` or `enp0s3`) to provide Internet access to WebSocket clients
* `wss_server_cert`, PEM formatted TLS server certificate file required for `wss://` support (and its optional key file `wss_server_key`)

Note that the values defined in `wsnic.conf.template` are the respective default values for settings left unspecified in `wsnic.conf`.

## Usage

Start `wsnic` using:
 
```bash
sudo ./wsnic.sh
```

Command line options:

```
$ ./wsnic.sh -h
usage: wsnic [-h] [-n NETBE] [-c CONF_FILE] [-v]

WebSocket to virtual network device proxy server.

options:
  -h, --help    show this help message and exit
  -n NETBE      use network backend NETBE (currently only default "brtap" supported)
  -c CONF_FILE  use configuration file CONF_FILE (default: wsnic.conf)
  -v            print verbose output
```

## WebSockets Secure support

WebSockets Secure (`wss://`) support is optional and only enabled if a TLS server certificate is defined in `wsnic.conf`, which means you need:

1. a DNS record for the hostname of your wsnic server
2. a TLS server certificate issued for that DNS hostname

If your wsnic server has a public DNS record for its hostname you should use a service like [Let’s Encrypt](https://letsencrypt.org/) to get a TLS certificate for it, otherwise you can create your own self-signed certificate as described in the next section.

To enable a TLS certificate declare it in `wsnic.conf` using:

```
wss_server_cert=/var/local/crt/cert.crt
wss_server_key=/var/local/crt/cert.key
```

WebSocket Secure URLs are of the form `wss://wsnic.example.com:8087`.

### Self-signed TLS server certificate

The following instructions use **`wsnic.example.com`** as the DNS hostname and **`/var/local/crt`** as the directory where TLS certificate files are stored, you need to replace both consistently according to your setup and network environment.

The DNS hostname doesn't need to be fully qualified in private networks, it might also be just `localhost` if wsnic (WebSocket server) and browser (WebSocket client) are running on the same machine.

Setting up a self-signed certificate involves two steps, after generating it you also have to configure your browser to accept it.

#### Step 1/2: Generate a self-signed certificate

To issue a basic self-signed TLS server certificate for DNS hostname `wsnic.example.com`:

```bash
mkdir /var/local/crt
cd /var/local/crt

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

## How it works

Overview of wsnic and its network components:

```
 +-----+     +-----+         +-----+
 | ws0 |     | ws1 |   ...   | wsN |    (WebSocket clients)
 +--+--+     +--+--+         +--+--+
    |           |               |
+===+===========+===============+====+
|   :           :               :    |  (wsnic WebSocket server)
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

* on startup, wsnic:
  * creates virtual bridge `wsbr0` and assigns it the subnet's first IP address,
  * optionally attaches `wsbr0` to the physical network adapter `eth0` using NAT,
  * optionally starts DHCP server `dnsmasq` and binds it to the IP address of `wsbr0`, and
  * starts operating as the WebSocket server, listening for WebSocket client connections
* after completing the handshake of a newly accepted WebSocket client connection `wsX`, wsnic:
  * creates a TAP device `wstapX`,
  * connects `wstapX` to `wsbr0`, and
  * begins passing ethernet frames between `wsX` and `wstapX`
* if a WebSocket client disconnects, wsnic removes the associated TAP device from the bridge (and network)
* DHCP server `dnsmasq` assigns DHCP leases to WebSocket clients, it is also the default DNS server
