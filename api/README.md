# nethsecurity-controller

## Build
```bash
CGO_ENABLED=0 go build
```

# Environment variables
**Mandatory**
- `ADMIN_USERNAME`: admin username to login
- `ADMIN_PASSWORD`: admin password to login
- `SECRET_JWT`: secret to sing JWT tokens

- `TOKENS_DIR`: directory to save authenticated tokens
- `CREDENTIALS_DIR`: directory to save credentials of connected units

- `PROMTAIL_ADDRESS`: promtail address
- `PROMTAIL_PORT`: promtail port

**Optional**
- `LISTEN_ADDRESS`: listend address of server - *default*: `127.0.0.1:5000`

- `OVPN_DIR`: openvpn configuration directory - *default*: `/etc/openvpn`
- `OVPN_NETWORK`: openvpn network address - *default*: `172.21.0.0`
- `OVPN_NETMASK`: openvpn netmask - *default*: `255.255.0.0`
- `OVPN_UDP_PORT`: openvpn udp port - *default*: `1194`

- `OVPN_C_DIR`: openvpn path of ccd directory - *default*: OVPN_DIR + `/ccd`
- `OVPN_P_DIR`: openvpn path of proxy directory - *default*: OVPN_DIR + `/proxy`
- `OVPN_K_DIR`: openvpn path of pki directory - *default*: OVPN_DIR + `/pki`
- `OVPN_M_SOCK`: opevpn management socket path - *default*: OVPN_DIR + `/run/mgmt.sock`

- `EASYRSA_PATH`: easyrsa command path - *default*: `/usr/share/easy-rsa/easyrsa`

- `PROXY_PROTOCOL`: traefik protocol - *default*: `http://`
- `PROXY_HOST`: traefik host - *default*: `localhost`
- `PROXY_PORT`: traefik port - *default*: `8080`
- `LOGIN_ENDPOINT`: unit login endpoint, on stand-alone api server - *default*: `/api/login`

- `FQDN`: fully qualified domain name of the machine - *default*: `hostname -f`

## APIs
### Auth
- `POST /login`

    REQ
    ```json
     Content-Type: application/json

     {
       "username": "root",
       "password": "Nethesis,1234"
     }
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200,
        "expire": "2023-05-25T14:04:03.734920987Z",
        "token": "eyJh...E-f0"
     }
    ```
- `POST /logout`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200
     }
    ```
- `GET /refresh`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200,
        "expire": "2023-05-25T14:04:03.734920987Z",
        "token": "eyJh...E-f0"
     }
    ```
### Units
- `GET /units`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200,
        "data": [
            {
                "ipaddress": "172.23.21.3",
                "id": "<unit_id>",
                "netmask": "255.255.255.0",
                "registered": true,
                "vpn": {
                    "bytes_rcvd": "21830",
                    "bytes_sent": "5641",
                    "connected_since": "1686312722",
                    "real_address": "192.168.122.220:41445",
                    "virtual_address": "172.23.21.3"
                },
                "info": {
                    "unit_id": "fba703c1-6c2d-4d3d-9dab-5998c7b66700",
                    "unit_name": "fw.local",
                    "version": "8-23.05.2-ns.0.0.2-beta2-37-g6e74afc",
                    "subscription_type": "enterprise",
                    "system_id": "XXXXXXXX-XXXX",
                    "created": "2024-03-14T15:18:08Z"
                }
            },
            ...
            {
                "ipaddress": "",
                "id": "<unit_id>",
                "netmask": "",
                "registered": false,
                "vpn": {},
                "info": {
                    "unit_id": "zzzzzzzz-d9f3-44b7-b277-36d65cf139e6",
                    "unit_name": "fw.nethsecurity.local",
                    "version": "8-23.05.2-ns.0.0.2-beta2-37-g6e74afc",
                    "subscription_type": "",
                    "system_id": "",
                    "created": "2024-03-14T15:16:02Z"
                }
            }
        ],
        "message": "units listed successfully"
     }
    ```
- `GET /units/<unit_id>`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200,
        "data": {
            "ipaddress": "172.23.21.3",
            "id": "<unit_id>",
            "netmask": "255.255.255.0",
            "registered": true,
            "vpn": {
                "bytes_rcvd": "22030",
                "bytes_sent": "5841",
                "connected_since": "1686312722",
                "real_address": "192.168.122.220:41445",
                "virtual_address": "172.23.21.3"
            },
            "info": {
                "unit_id": "fba703c1-6c2d-4d3d-9dab-5998c7b66700",
                "unit_name": "fw.local",
                "version": "8-23.05.2-ns.0.0.2-beta2-37-g6e74afc",
                "subscription_type": "enterprise",
                "system_id": "XXXXXXXX-XXXX",
                "created": "2024-03-14T15:18:08Z"
            }
        },
        "message": "unit listed successfully"
     }
    ```
- `GET /units/<unit_id>/token`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200,
        "data": {
            "expire": "2023-06-10T12:23:39.46160793Z",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...rRikiEG83smBWPdHWzzhKOnfgzOkRXQntxdKGdaIhk8"
        },
        "message": "unit token retrieved successfully"
     }
    ```
- `POST /units`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>

     {
        "unit_id": "<unit_id>"
     }
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200,
        "data": {
            "ipaddress": "172.21.0.5"
        },
        "message": "unit added successfully"
     }
    ```
- `POST /units/register`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>

     {
        "unit_name": "fw.nethsecurity.local",
        "unit_id": "d330b2db-cdfe-4c56-b9b6-f97e5b838748",
        "username": "test",
        "password": "Nethesis,1234",
        "version": "8-23.05.2-ns.0.0.2-beta2-37-g6e74afc",
        "subscription_type": "enterprise",
        "system_id": "XXXXXXXX-XXXX",
     }
    ```

    RES | unit previously added
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200,
        "data": {
            "ca": "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----",
            "cert": "Certificate:\n\n-----END CERTIFICATE-----",
            "host": "ns8.local",
            "key": "-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----",
            "port": "1194",
            "promtail_address": "172.21.0.1",
            "promtail_port": "5151"
        },
        "message": "unit registered successfully"
     }
    ```

    RES | unit not added in waiting list
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 403,
        "data": "",
        "message": "unit added to waiting list"
     }
    ```
- `DELETE /units/<unit_id>`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
        "code": 200,
        "data": "",
        "message": "unit deleted successfully"
     }
    ```