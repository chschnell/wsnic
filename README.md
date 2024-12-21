**wsnic** is a WebSocket to TAP device proxy server for linux.

* passes IEEE 802.3 [ethernet frames](https://en.wikipedia.org/wiki/Ethernet_frame) between a local [TAP device](https://en.wikipedia.org/wiki/TUN/TAP) and an open number of WebSocket clients (OSI layer 2)
* uses [sans-io WebSocket](https://websockets.readthedocs.io/en/stable/reference/sansio/server.html) server protocol implementation from [websockets](https://websockets.readthedocs.io/en/stable/)
* uses [scapy](https://scapy.net/) to provide a simple DHCP service tied to the TAP device for WebSocket clients
* uses a single [epoll](https://docs.python.org/3/library/select.html#edge-and-level-trigger-polling-epoll-objects)-loop for all sockets and the TAP device
* sends periodic PINGs to idle WebSocket clients

## Installation

After cloning this repository, install `websockets` and `scapy` using pip into your working copy:

```bash
cd wsnic
python3 -m venv venv
venv/bin/pip3 install websockets scapy
```

Copy [`wsnic.conf.template`](./wsnic.conf.template) to `wsnic.conf` and edit as needed. Start `wsnic` using:

```bash
sudo ./wsnic.py
```

## Optional: wss-to-ws conversion with Apache2 (Debian 12)

*NOTE: This is still WIP*

**Install Apache2 and enabke required modules:**

```
sudo apt install apache2

sudo a2ensite default-ssl
sudo a2enmod ssl proxy proxy_http proxy_wstunnel
```

**Create a self-signed certificate:**

```
cd /path/to/certificate

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cert.key -out cert.crt -subj "/CN=build-any" \
  -addext "subjectAltName=DNS:build-any.rekoba.de,DNS:localhost,IP:10.0.10.74"
```

**Edit default-ssl.conf:**

```
sudo nano /etc/apache2/sites-available/default-ssl.conf

<VirtualHost *:443>
    ServerName           ...
    ServerAlias          ...

    SSLCertificateFile    /path/to/certificate/cert.crt
    SSLCertificateKeyFile /path/to/certificate/cert.key

    SSLProxyEngine On
    ProxyPass /wsnic http://127.0.0.1:8070/ upgrade=websocket
</VirtualHost>
```
