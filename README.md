# nethsecurity-controller

The controller (server) is a set of containers that allow the admin to remotely manage multiple [NethSecurity](https://github.com/NethServer/nethsecurity) installations (firewalls).

Firewalls can register to the server using [ns-plug](https://github.com/NethServer/nethsecurity/tree/master/packages/ns-plug) client. Upon registration the server will:
- create a VPN configuration which is sent back to the firewall
- create a route inside the proxy to access the firewall Luci RPC
- store credentials to access the remote firewall

## Quickstart

You can install it on [NS8](https://github.com/NethServer/ns8-nethsecurity-controller#install).

Otherwise, first make sure to have [podman](https://podman.io/) installed on your server.
Containers should run under non-root users, but first you need to configure the tun device and the user.

As root, execute:
```
useradd -m controller
loginctl enable-linger controller

ip tuntap add dev tunsec mod tun
ip addr add 172.21.0.1/16 dev tunsec
ip link set dev tunsec up
```

Then change to non-root user, clone this repository and execute:
```
su - controller

./start.sh
```

The server will be available at `http://<fqdn>:8080/ui`.

## How it works

General workflow:

1. Access the controller and add a new machine using the `add` API below. This will generate a join code containing the FQDN of the controller, a registration token, and the unit UUID.
2. Connect the NethSecurity unit and register the machine using the join code.
3. Return to the controller and manage the unit.
  - The UI retrieves a token for the NethSecurity unit: `curl http://localhost:8080/api/servers/login/clientX`
  - THe UI Uses the token to invoke Luci APIs: `curl http://localhost:8080/clientX/cgi-bin/luci/rpc/...`


### Services

The controller is composed by 4 services:
- nethsec-vpn: OpenVPN server, it authenticates the machines and create routes for the proxy, it listens on port 1194
- nethsec-proxy: traefik forwards requests to the connected machines using the machine name as path prefix, it listens on port 8181
- nethsec-api: REST API python server to manage nethsec-vpn clients, it listens on port 5000
- nethsec-ui: lighttpd instance serving static UI files, it listens on port 3000

## Environment configuration

The following environment variables can be used to configure the containers:

- `FQDN`: default is the container/pod hostname
- `OVPN_NETWORK`: OpenVPN network, default is `172.21.0.0`
- `OVPN_NETMASK`: OpenVPN netmask, default is `255.255.0.0`
- `OVPN_CN`: OpenVPN certificate CN, default is `nethsec`
- `OVPN_UDP_PORT`: OpenVPN UDP port, default is `1194`
- `OVPN_TUN`: OpenVPN tun device name, default is `tunsec`
- `UI_PORT`: UI listening port, default is `3000`
- `UI_BIND_IP`: UI binding IP, default is `0.0.0.0`
- `API_PORT`: API server listening port, default is `5000`
- `API_BIND_IP`: API server listening IP, default is `127.0.0.1`
- `API_USER`: controller admin user, default is `admin`
- `API_PASSWORD`: controller admin password, it must be passed as SHA56SUM, default is `admin`
- `API_SECRET`: JWT secret token
- `API_DEBUG`: enable debug logging and CORS if set to `1`, default is `0`
- `API_SESSION_DURATION`: JWT session duration in seconds, default is 7 days
- `PROXY_PORT`: proxy listening port, default is `8080`
- `PROXY_BIND_IP`: proxy binding IP, default is `0.0.0.0`
- `REPORT_DB_URI`: Timescale DB URI, like `postgresql://user:password@host:port/dbname`

## REST API

Manage server registrations using the REST API server.
Request should be sent to the proxy server.

Almost all APIs are authenticated using [JWT](https://flask-jwt-extended.readthedocs.io/en/stable/).

Authentication work-flow:

1. send user name and password to `/login` API
2. retrieve authorization tokens:
   - `access_token`: it's the token used to executed all APIs, it expires after an hour
   - `refresh_token`: this token can be used only to call the `/refresh` API and request a new `access_token`, it expires after `API_SESSION_DURATION` seconds (default to 7 days) 
3. invoke other APIs by setting the header `Authorization: Bearer <access_token>"`

Unauthenticated APIs:

- `/login`: execute the login and retrieve the tokens
- `/register`: invoked by firewalls to register themselves, this API should be always invoked using a valid HTTPS endpoint to
  ensure the identity of the server

See the [API documentation](api/README.md) for more details.

## Build

Each container is build using a Containerfile, which is both compatible with `docker build` command and `podman build`.

To build the images using podman, you can use the following:

```bash
podman build --target dist --layers --force-rm --jobs 0 <directory>
```

Where `<directory>` is the path to any of the directory to build the container of.

Optionally, you can add the `--tag <imagetag>` to tag the image with a specific name.
