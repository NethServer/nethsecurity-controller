#!/bin/sh

mkdir -p /etc/openvpn/sockets

cd /nethsec-api
source /nethsec-api/bin/activate

exec python3 api.py
