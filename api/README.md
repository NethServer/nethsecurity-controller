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
- `REGISTRATION_TOKEN`: secret token used to register units

- `TOKENS_DIR`: directory to save authenticated tokens
- `CREDENTIALS_DIR`: directory to save credentials of connected units

- `PROMTAIL_ADDRESS`: promtail address
- `PROMTAIL_PORT`: promtail port

- `PROMETHEUS_PATH`: prometheus web path
- `WEBSSH_PATH`: webssh web path
- `GRAFANA_PATH`: grafana web path
- `GRAFANA_POSTGRES_PASSWORD`: password to access grafana postgres database
- `REPORT_DB_URI`: Timescale database URI for reports

**Optional**

- `LISTEN_ADDRESS`: listend address of server - _default_: `127.0.0.1:5000`

- `OVPN_DIR`: openvpn configuration directory - _default_: `/etc/openvpn`
- `OVPN_NETWORK`: openvpn network address - _default_: `172.21.0.0`
- `OVPN_NETMASK`: openvpn netmask - _default_: `255.255.0.0`
- `OVPN_UDP_PORT`: openvpn udp port - _default_: `1194`

- `OVPN_C_DIR`: openvpn path of ccd directory - _default_: OVPN_DIR + `/ccd`
- `OVPN_P_DIR`: openvpn path of proxy directory - _default_: OVPN_DIR + `/proxy`
- `OVPN_K_DIR`: openvpn path of pki directory - _default_: OVPN_DIR + `/pki`
- `OVPN_M_SOCK`: opevpn management socket path - _default_: OVPN_DIR + `/run/mgmt.sock`

- `EASYRSA_PATH`: easyrsa command path - _default_: `/usr/share/easy-rsa/easyrsa`

- `PROXY_PROTOCOL`: traefik protocol - _default_: `http://`
- `PROXY_HOST`: traefik host - _default_: `localhost`
- `PROXY_PORT`: traefik port - _default_: `8080`
- `LOGIN_ENDPOINT`: unit login endpoint, on stand-alone api server - _default_: `/api/login`

- `FQDN`: fully qualified domain name of the machine - _default_: `hostname -f`

- `CACHE_TTL`: cache time to live for unit information in seconds - _default_: `7200` (2 hours)
  Unit information are fetched from the connected units. The cache is refreshed every hour.

- `RETENTION_DAYS`: configure how many days the metrics should be kept - _default_: `60`

- `MAXMIND_LICENSE`: license key for maxmind geolite2 database - _default_: ``
  If the license key is not set, the geolite2 database will not be downloaded.
- `GEOIP_DB_DIR`: directory to save geolite2 database - _default_: current directory

- `SENSITIVE_LIST`: list of sensitive information to be redacted in logs
- `VALID_SUBSCRIPTION`: valid subscription status - _default_: `false`

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
              "vpn": {
                  "bytes_rcvd": "21830",
                  "bytes_sent": "5641",
                  "connected_since": "1686312722",
                  "real_address": "192.168.122.220:41445",
                  "virtual_address": "172.23.21.3"
              },
              "info": {
                  "unit_name": "myfw1",
                  "version": "8-23.05.2-ns.0.0.2-beta2-37-g6e74afc",
                  "subscription_type": "enterprise",
                  "system_id": "XXXXXXXX-XXXX",
                  "ssh_port": 22,
                  "fqdn": "fw.local",
                  "api_version": "1.0.0"
              }
          },
          ...
          {
              "ipaddress": "",
              "id": "<unit_id>",
              "netmask": "",
              "vpn": {},
              "info": {
                  "unit_name": "",
                  "version": "",
                  "subscription_type": "",
                  "system_id": "",
                  "ssh_port": 0,
                  "fqdn": "",
                  "api_version": "1.0.0"
              }
          }
      ],
      "message": "units listed successfully"
   }
  ```

  The API takes a query parameter `cache`. If `cache` is set to `true`, the API will return the cached data, if data are fresh enough.
  If `cache` is set to `false`, the API will always fetch the data from the connected units.

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
              "unit_name": "myfw1",
              "version": "8-23.05.2-ns.0.0.2-beta2-37-g6e74afc",
              "subscription_type": "enterprise",
              "system_id": "XXXXXXXX-XXXX",
              "ssh_port": 22,
              "fqdn": "fw.local",
              "api_version": "1.0.0"
          },
          "join_code": "eyJmcWRuIjoiY29udHJvbGxlci5ncy5uZXRoc2VydmVyLm5ldCIsInRva2VuIjoiMTIzNCIsInVuaXRfaWQiOiI5Njk0Y2Y4ZC03ZmE5LTRmN2EtYjFjNC1iY2Y0MGUzMjhjMDIifQ=="
      },
      "message": "unit listed successfully"
   }
  ```

  The API takes a query parameter `cache`. If `cache` is set to `true`, the API will return the cached data, if data are fresh enough.
  If `cache` is set to `false`, the API will always fetch the data from the connected units.

- `GET /units/<unit_id>/info`

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
          "fqdn": "NethSec",
          "ssh_port": 22,
          "subscription_type": "enterprise",
          "system_id": "XXXXXXXX-XXXX",
          "unit_name": "NethSec",
          "version": "NethSecurity 8 23.05.3-ns.1.0.1",
          "api_version": "1.0.0"
      },
      "message": "unit info retrieved successfully"
   }
  ```

  The API saves unit information in `OVPN_S_DIR` with `.info` extension. This is useful for retrieving new information of the unit without waiting for cron to store it.

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
          "join_code": "eyJmcWRuIjoiY29udHJvbGxlci5ncy5uZXRoc2VydmVyLm5ldCIsInRva2VuIjoiMTIzNCIsInVuaXRfaWQiOiI2OThhMDQzZC02MGRiLTQyNmMtODRjZi1lODZhMTZmM2QxMzMifQ=="
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

### Accounts

- `GET /accounts`

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
          "accounts": [
          {
              "id": 2,
              "username": "test1",
              "password": "",
              "display_name": "Test 1",
              "created": "2024-03-14T09:37:28+01:00"
          },
          ...
          {
              "id": 6,
              "username": "test2",
              "password": "",
              "display_name": "Test 2",
              "created": "2024-03-14T11:43:33+01:00"
          }
          ],
          "total": 5
      },
      "message": "success"
   }

  ```

- `GET /accounts/<account_id>`

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
          "account": {
          "id": 2,
          "username": "test3",
          "password": "",
          "display_name": "Test 3",
          "created": "2024-03-14T09:37:28+01:00"
          }
      },
      "message": "success"
   }
  ```

- `POST /accounts`

  REQ

  ```json
   Content-Type: application/json
   Authorization: Bearer <JWT_TOKEN>

   {
      "username": "test1",
      "password": "Nethesis,1234",
      "display_name": "Test 1"
   }
  ```

  RES

  ```json
   HTTP/1.1 201 OK
   Content-Type: application/json; charset=utf-8

   {
      "code": 201,
      "data": null,
      "message": "success"
   }
  ```

- `PUT /accounts/<account_id>`

  REQ

  ```json
   Content-Type: application/json
   Authorization: Bearer <JWT_TOKEN>

   {
      "password": "Nethesis,4321",
      "display_name": "Test 5"
   }
  ```

  RES

  ```json
   HTTP/1.1 200 OK
   Content-Type: application/json; charset=utf-8

   {
      "code": 200,
      "data": null,
      "message": "success"
   }
  ```

- `PUT /accounts/password`

  REQ

  ```json
   Content-Type: application/json
   Authorization: Bearer <JWT_TOKEN>

   {
      "old_password": "Nethesis,1234",
      "new_password": "Nethesis,4321"
   }
  ```

  RES

  ```json
   HTTP/1.1 200 OK
   Content-Type: application/json; charset=utf-8

   {
      "code": 200,
      "data": null,
      "message": "success"
   }
  ```

- `DELETE /accounts/<account_id>`

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
      "message": "success"
   }
  ```

- `GET /accounts/ssh-keys`

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
          "key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...m3XHi7DiRCmyqbwdp86eV\n-----END OPENSSH PRIVATE KEY-----",
          "key_pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVled...UxVF6O0Esc3gFe0XMUT9Y+GtqM1O2s= test@local.domain"
      },
      "message": "success"
   }
  ```

- `POST /accounts/ssh-keys`

  REQ

  ```json
   Content-Type: application/json
   Authorization: Bearer <JWT_TOKEN>

   {
      "passphrase": "Nethesis,2222"
   }
  ```

  RES

  ```json
   HTTP/1.1 201 OK
   Content-Type: application/json; charset=utf-8

   {
      "code": 200,
      "data": {
          "key_pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVled...UxVF6O0Esc3gFe0XMUT9Y+GtqM1O2s= test@local.domain"
      },
      "message": "success"
   }
  ```

- `DELETE /accounts/ssh-keys`

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
      "message": "success"
   }
  ```

### Defaults

- `GET /defaults`

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
          "fqdn": "controller.ns8.local",
          "grafana_path": "/grafana",
          "prometheus_path": "/prometheus",
          "webssh_path": "/webssh",
          "valid_subscription": false
      },
      "message": "success"
   }
  ```

### Ingest

This API is used to ingest metrics from connected units. It requires basic authentication and 
takes `firewall_api` as a parameter. 
The `firewall_api` paramater is the name of the firewall API that is sending the metrics.
The API accepts only POST requests abd requires the following headers:

- `Authorization:`: basic authentication header, where the username is the unit uuid and the password is the registration token
- `Content-Type: application/json`: the content type must be JSON

It responds with a 200 status code in case of success. Success example:
```json
{"code":200,"data":null,"message":"success"}
```

Possible error status codes are:

- 400 if the request is malformed
- 401 if the authentication headers are missing or invalid
- 500 if there is an internal server error

Error example:

```json
{ "code": 401, "data": null, "message": "invalid unit id" }
```

- `POST /ingest/dump-nsplug-config`

  Create the unit record where all metrics are connected, it also stores the unit name in the report database.
  This endpoint is mandatory and must be called at least once before sending all other metrics.

  REQ

  ```json
  { "name": "fw.test.local" }
  ```

- `POST /ingest/dump-mwan-events`

  Store all multiwan events in the report database.

  REQ

  ```json
  { "data": [
    {
      "timestamp": 1726819981,
      "wan": "wan",
      "interface": "eth1",
      "event": "online"
    },
    {
      "timestamp": 1726820241,
      "wan": "wan2",
      "interface": "eth2",
      "event": "offline"
    },
  ]}
  ```

- `POST /ingest/dump-ts-attacks`

  Store all threat shield brute force blocks (fail2ban-like) in the report database.

  REQ

  ```json
  { "data": [
    {
      "timestamp": 1726812650,
      "ip": "200.91.234.36"
    }
  ]}
  ```

- `POST /ingest/dump-ts-malware`

  Store all threat shield blocks based on category in the report database.

  REQ

  ```json
  { "data": [
    {
      "timestamp": 1726811160,
      "src": "5.6.32.54",
      "dst": "1.2.3.4",
      "category": "nethesislvl3v4",
      "chain": "inp-wan"
    }
  ]}
  ```

- `POST /ingest/dump-ovpn-connections`

  Store all openvpn connections in the report database.

  REQ

  ```json
  { "data": [
    {
      "timestamp": 1726812276,
      "instance": "ns_roadwarrior1",
      "common_name": "user1",
      "virtual_ip_addr": "10.9.10.41",
      "remote_ip_addr": "1.2.3.4",
      "start_time": 1726819476,
      "duration": 4,
      "bytes_received": 16343,
      "bytes_sent": 7666
    }
  ]}
  ```

- `POST /ingest/dump-dpi-stats`

  Store all network traffic stats in the report database.

  REQ

  ```json
  { "data": [
    {
      "timestamp": 1726819203,
      "client_address": "fe80::10ac:f709:5fb8:8fc3",
      "client_name": "host1.test.local",
      "protocol": "mdns",
      "bytes": 123
    }
  ]}
  ```

  ```

- `POST /ingest/dump-ovpn-config`

  Store the openvpn configuration in the report database.

  REQ
  ```json
  {"data": [{"instance": "ns_roadwarrior1", "device": "tunrw1", "type": "rw", "name": "srv1"}]}
  ```

- `POST /ingest/dump-wan-config`

  REQ

  ```json
  {"data": [{"interface": "wan1", "device": "eth0", "status": "online"}, {"interface": "wan2", "device": "eth5", "status": "offline"}]}
  ```
