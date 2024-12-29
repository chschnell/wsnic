**wsnic** is a WebSocket to TAP device proxy server for linux.

* passes IEEE 802.3 [ethernet frames](https://en.wikipedia.org/wiki/Ethernet_frame) between an open number of WebSocket clients and local [TAP devices](https://en.wikipedia.org/wiki/TUN/TAP)
* uses the [sans-io WebSocket](https://websockets.readthedocs.io/en/stable/reference/sansio/server.html) server protocol implementation from [websockets](https://websockets.readthedocs.io/en/stable/)
* maintains a separate TAP device for each WebSocket connection
* provides a built-in DHCP service answering to WebSocket clients
* uses a single [epoll](https://docs.python.org/3/library/select.html#edge-and-level-trigger-polling-epoll-objects)-loop for all sockets and TAP devices
* sends periodic PINGs to idle WebSocket clients

## Installation

After cloning this repository, install `websockets` into your working copy using pip:

```bash
cd wsnic
python3 -m venv venv
venv/bin/pip3 install websockets
```

Copy [`wsnic.conf.template`](./wsnic.conf.template) to `wsnic.conf` and edit as needed.

## Usage

Start `wsnic` using:
 
```bash
sudo ./wsnic.sh
```

Command line options:

```
$ ./wsnic.sh -h
usage: wsnic [-h] [-c CONF_FILE] [-v]

WebSocket to TAP device proxy server.

options:
  -h, --help    show this help message and exit
  -c CONF_FILE  use configuration file CONF_FILE (default: wsnic.conf)
  -v            print verbose output
```

## Network architecture

```
+----------------+   +----------------+   +----------------+
| WebSock Client |   | WebSock Client |   | WebSock Client |
|   via wsnic0   |   |   via wsnic1   |   |   via wsnicN   |
+--------+-------+   +--------+-------+   +--------+-------+
         |                    |                    |
+--------+-------+   +--------+-------+   +--------+-------+
|  wsnic0 (TAP)  |   |  wsnic1 (TAP)  |   |  wsnicN (TAP)  |
|  192.168.10.2  |   |  192.168.10.3  |   |  192.168.10.N  |
+--------+-------+   +--------+-------+   +--------+-------+
         |                    |                    |
         +--------------------+--------------------+
                              |                     
                  +-----------+----------+    + - - - -+
                  |     wsnicbr0 (BR)    |....:  DHCP  :
                  |   IP: 192.168.10.1   |    : Server :
                  +-----------+----------+    +- - - - +
                              |
                  NAT (iptables MASQUERADE)
                              |
                  +-----------+----------+
                  |      eth0 (NIC)      |
                  |   External Network   |
                  +----------------------+
```

## Optional: wss-to-ws conversion with Apache2 (Debian 12)

*NOTE: This is still WIP*

**Install Apache2 and enable required modules:**

```
sudo apt install apache2

sudo a2ensite default-ssl
sudo a2enmod ssl proxy proxy_http proxy_wstunnel
```

**Create a self-signed certificate:**

You must replace `PRIMARY_HOSTNAME` with the hostname of your Apache2 server. Using the optional extension `subjectAltName` you may add any number of alternate `DNS` (replace `ALT_HOSTNAME`) and/or `IP` (replace `IP_ADDRESS`) addresses to the generated certificate.

```
cd /path/to/certificate

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout cert.key -out cert.crt -subj "/CN=PRIMARY_HOSTNAME" \
  -addext "subjectAltName=DNS:ALT_HOSTNAME,IP:IP_ADDRESS"
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
