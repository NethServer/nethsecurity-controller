#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo or log in as root."
    exit 1
fi

# This script manages a Docker Compose stack for the NethSecurity project.
# It can start or stop containers (VPN, API, UI, Proxy, and TimescaleDB) using Docker Compose.

image_tag=${IMAGE_TAG:-latest}
COMPOSE_FILE="docker-compose.yml"

start_pod() {
    # Check if network device tunsec exists, if not create it with sudo
    if ! ip link show dev tunsec > /dev/null 2>&1; then
        echo "Network device tunsec does not exist, creating it with root privileges..."
        ip tuntap add dev tunsec mode tun
        ip addr add 172.21.0.1/16 dev tunsec
        ip link set dev tunsec up
    fi

    # Check if UFW is installed and enable port 443 if it's not already open
    if command -v ufw >/dev/null 2>&1; then
        if ! ufw status | grep -q "443/tcp.*ALLOW"; then
            echo "Opening port 443/tcp in firewall..."
            ufw allow 443/tcp
        fi
    fi

    echo "Starting NethSecurity stack with image tag $image_tag, FQDN: $FQDN"
    
    # Generate WEBSSH_PATH if not set
    export IMAGE_TAG=$image_tag
    # Set FQDN if not already set
    export FQDN=${FQDN:-$(hostname -f)}
    docker compose -f $COMPOSE_FILE up
    echo "NethSecurity stack started successfully"
}

stop_pod() {
    echo "Stopping NethSecurity stack"
    docker compose -f $COMPOSE_FILE down
    echo "NethSecurity stack stopped"
}

case "$1" in
    start)
        start_pod
        ;;
    stop)
        stop_pod
        ;;
    restart)
        stop_pod
        start_pod
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac
