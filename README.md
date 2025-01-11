**wsnic** is a WebSocket to virtual network device proxy server for linux.

* passes IEEE 802.3 [ethernet frames](https://en.wikipedia.org/wiki/Ethernet_frame) between a Linux network and an open number of WebSocket clients
* creates a single [bridge](https://wiki.archlinux.org/title/Network_bridge) and one [TAP device](https://en.wikipedia.org/wiki/TUN/TAP) per WebSocket client
* supports attaching the bridge to a physical network device using Network Address Translation (NAT) to grant Internet-access to WebSocket clients
* uses the [sans-io WebSocket](https://websockets.readthedocs.io/en/stable/reference/sansio/server.html) server protocol implementation from [websockets](https://websockets.readthedocs.io/en/stable/)
* supports WebSockets Secure (`wss://`) connections by offloading to [stunnel](https://www.stunnel.org/)
* uses [`dnsmasq`](https://thekelleys.org.uk/dnsmasq/doc.html) to provide DHCP and DNS services to WebSocket clients
* uses a single-threaded [epoll](https://docs.python.org/3/library/select.html#edge-and-level-trigger-polling-epoll-objects)-loop for all sockets and network devices
* sends periodic PINGs to idle WebSocket clients

## Installation

Instructions below are tested with Debian 12 (Bookworm) netinst (without Desktop).

#### Step 1/3: Install required linux tools

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

#### Step 2/3: Clone and initialize this repository

Clone a working copy of this repository. Then, install `websockets` into the working copy using `pip`:

```bash
git clone https://github.com/chschnell/wsnic.git

cd wsnic
python3 -m venv venv
venv/bin/pip3 install websockets
cd ..
```

#### Step 3/3: Installation setup

Copy [`wsnic.conf.template`](./wsnic.conf.template) to `wsnic.conf` and edit as needed, settings to consider:

* `eth_iface`, the physical interface defaults to `eth0` but could be something different like `enp0s3`, check with command `ip addr`.
* `wss_server_cert`, PEM formatted TLS server certificate file required for `wss://` support (and its optional key file `wss_server_key`)
* `subnet`, the IP subnet that wsnic will use, it defaults to `192.168.2.0/24` which might collide with your local network configuration and must then be changed accordingly
* `dhcp_domain_name` and `dhcp_domain_name_server`, the DNS domain name and DNS domain name server(s) to be used in DHCP replies

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
  -n NETBE      use network backend NETBE (tapdev, brtap, brveth or pktsock; default: tapdev)
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

WebSocket Secure URLs are of the form `wss://wsnic.example.com:8071`.

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
https://wsnic.example.com:8071
```

You will get a security warning that you need to acknowledge once to grant permission permanently. After that you should see a reply page from wsnic's WebSocket server that reads:

```
Failed to open a WebSocket connection: invalid Connection header: keep-alive.

You cannot access a WebSocket server directly with a browser. You need a WebSocket client.
```

This seeming error message is in fact our expected success message here, if you see it then things are working as they should and you can close the browser tab.
