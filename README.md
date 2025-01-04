**wsnic** is a WebSocket to virtual network device proxy server for linux.

* passes IEEE 802.3 [ethernet frames](https://en.wikipedia.org/wiki/Ethernet_frame) between a configurable network backend and an open number of WebSocket clients
* supports different network backend configurations using linux network [TAP devices](https://en.wikipedia.org/wiki/TUN/TAP) and [bridges](https://wiki.archlinux.org/title/Network_bridge)
* uses the [sans-io WebSocket](https://websockets.readthedocs.io/en/stable/reference/sansio/server.html) server protocol implementation from [websockets](https://websockets.readthedocs.io/en/stable/)
* supports WebSockets Secure (`wss://`) connections by offloading to [stunnel](https://www.stunnel.org/)
* provides built-in DHCP service on the network backend answering to WebSocket clients
* uses a single-threaded [epoll](https://docs.python.org/3/library/select.html#edge-and-level-trigger-polling-epoll-objects)-loop for all sockets and  network devices
* sends periodic PINGs to idle WebSocket clients

## Installation

First, make sure that the required linux tools `ip`, `iptables` and `stunnel` (stunnel is optional and only needed for `wss://` support) are installed, for Debian:

```bash
sudo apt install iproute2 iptables stunnel
```

Clone a working copy of this repository. Next, install `websockets` into your working copy using `pip`:

```bash
cd wsnic
python3 -m venv venv
venv/bin/pip3 install websockets
```

Copy [`wsnic.conf.template`](./wsnic.conf.template) to `wsnic.conf` and edit as needed, settings to consider:

* `eth_iface=eth0`, the physical interface defaults to `eth0` but could be something different like `enp0s3`, you can check with command `ip addr`.
* `wss_server_cert` and `wss_server_key`, TLS server certificate and key file, required for `wss://` support
* `subnet=192.168.2.0/24`, the IP subnet that wsnic will use, this might collide with your private network configuration and must then be changed accordingly
* `dhcp_domain_name` and `dhcp_domain_name_server`, the DNS domain name and DNS domain name server(s) to be used in DHCP replies

## Usage

Start `wsnic` using:
 
```bash
sudo ./wsnic.sh
```

Command line options:

```
$ ./wsnic.sh -h
usage: wsnic [-h] [-n NETBE] [-c CONF_FILE] [-v]

WebSocket to TAP device proxy server.

options:
  -h, --help    show this help message and exit
  -n NETBE      use network backend NETBE (tapdev, brtap, brveth or pktsock; default: tapdev)
  -c CONF_FILE  use configuration file CONF_FILE (default: wsnic.conf)
  -v            print verbose output
```

## WebSockets Secure support

WebSockets Secure (`wss://`) support is optional and only enabled if a TLS server certificate is defined in `wsnic.conf`, this implies that you have:

1. a DNS record for the hostname of your wsnic server
2. a TLS server certificate issued for that DNS hostname

If your wsnic server has a public DNS record for its hostname you should use a service like [Let�s Encrypt](https://letsencrypt.org/) to get a TLS certificate for it, otherwise you can create your own self-signed certificate as described in the next section.

WebSocket Secure URL format for the browser is `wss://wsnic.example.com:8071` (for DNS hostname `wsnic.example.com` and wss port `8071`).

### Self-signed TLS server certificate

The following instructions use **`wsnic.example.com`** as the DNS hostname and **`/var/local/crt`** as the directory where TLS certificate files are stored, you need to replace both consistently according to your setup and network environment.

The DNS hostname doesn't need to be fully qualified in private networks, it might also be `localhost` if wsnic and browser are running on the same machine.

Setting up a self-signed certificate involves two steps, after generating it you also have to configure your browser to accept it.

#### Step 1: Generate a self-signed certificate

To issue a simple certificate in directory `/var/local/crt` for hostname `wsnic.example.com` enter:

```bash
mkdir /var/local/crt
cd /var/local/crt

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cert.key -out cert.crt -subj "/CN=wsnic.example.com"
```

If needed, you can issue the certificate for additional DNS names and/or IP addresses, here an example that adds DNS name `wsnic2.example.com` and IP address `12.34.56.78`:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cert.key -out cert.crt -subj "/CN=wsnic.example.com" \
  -addext "subjectAltName=DNS:wsnic2.example.com,IP:12.34.56.78"
```

You can add multiple alternate DNS names and IP addresses, use comma `,` to separate them.

#### Step 2: Setup browser to accept the self-signed certificate

By default, modern browsers refuse to connect to HTTPS and WebSocket servers with self-signed TLS certificates. In order to get around that you have to grant permission in your browser once by pointing it at your wsnic server using a HTTPS URL:

```
https://wsnic.example.com:8071
```

You will get a security warning that you need to acknowledge once. After that you should see a reply page from wsnic's WebSocket server that reads:

```
Failed to open a WebSocket connection: invalid Connection header: keep-alive.

You cannot access a WebSocket server directly with a browser. You need a WebSocket client.
```
