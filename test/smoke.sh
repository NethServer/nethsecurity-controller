#!/bin/bash

set -e

# Smoke test script for NethSecurity Controller
# This script builds all containers, starts the stack, and verifies all services are running

BASE_URL="http://localhost:5000"
POD="nethsecurity-pod"
SCRIPT_DIR=$(cd "$(dirname "$0")/.." && pwd)

echo "=== NethSecurity Controller Smoke Test ==="
echo

# Clean up function
cleanup() {
    echo "Cleaning up..."
    cd "$SCRIPT_DIR"
    ./dev.sh stop 2>/dev/null || true
}

trap cleanup EXIT

# Check prerequisites
echo "Checking prerequisites..."
for cmd in podman buildah curl jq; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is not installed"
        exit 1
    fi
done

# Check tunsec device
if ! ip link show dev tunsec > /dev/null 2>&1; then
    echo "Error: tunsec network device does not exist"
    echo "Create it with:"
    echo "  sudo ip tuntap add dev tunsec mod tun"
    echo "  sudo ip addr add 172.21.0.1/16 dev tunsec"
    echo "  sudo ip link set dev tunsec up"
    exit 1
fi

echo "Prerequisites OK"
echo

IMAGE_TAG=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
if [ -z "$IMAGE_TAG" ] || [ "$IMAGE_TAG" = "HEAD" ]; then
    IMAGE_TAG=$(git rev-parse --short HEAD)
fi
echo "Current tag: $IMAGE_TAG"
echo

# Build containers
echo "Building containers..."
cd "$SCRIPT_DIR"
./build.sh

echo
echo "Containers built successfully"
podman images
echo

# Stop any existing pod
echo "Stopping any existing pod..."
./dev.sh stop 2>/dev/null || true
sleep 2

# Start the stack with branch name as image tag
echo "Starting the stack with IMAGE_TAG=$IMAGE_TAG..."
IMAGE_TAG="$IMAGE_TAG" ./dev.sh start

# Wait for API to be ready
echo "Waiting for API server to be ready..."
for i in {1..60}; do
    if curl -s -f "$BASE_URL/health" > /dev/null 2>&1; then
        echo "API server is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "Error: API server did not become ready in time"
        podman logs nethsecurity-pod-api
        exit 1
    fi
    sleep 1
done

# Check all containers are running
echo
echo "Checking all containers are running..."
for container in nethsecurity-pod-vpn nethsecurity-pod-db nethsecurity-pod-api nethsecurity-pod-ui nethsecurity-pod-proxy; do
    if ! podman ps --filter name=$container --format "{{.Status}}" | grep -q "Up"; then
        echo "Error: Container $container is not running"
        podman ps -a
        exit 1
    fi
    echo "  ✓ $container is running"
done

# Test login
echo
echo "Testing login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}')

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    echo "Error: Login failed"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi
echo "  ✓ Login successful"

# Test adding a unit
echo
echo "Testing unit creation..."
UNIT_ID=$(uuidgen)
ADD_RESPONSE=$(curl -s -X POST "$BASE_URL/units" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"unit_id\":\"$UNIT_ID\",\"subscription\":\"active\"}")

if ! echo "$ADD_RESPONSE" | jq -e '.code == 200' > /dev/null; then
    echo "Error: Failed to add unit"
    echo "Response: $ADD_RESPONSE"
    exit 1
fi
echo "  ✓ Unit created successfully"

# Test retrieving the unit
echo
echo "Testing unit retrieval..."
UNIT_RESPONSE=$(curl -s -X GET "$BASE_URL/units/$UNIT_ID" \
    -H "Authorization: Bearer $TOKEN")

if ! echo "$UNIT_RESPONSE" | jq -e '.code == 200' > /dev/null; then
    echo "Error: Failed to retrieve unit"
    echo "Response: $UNIT_RESPONSE"
    exit 1
fi
echo "  ✓ Unit retrieved successfully"

# Test health endpoint
echo
echo "Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s "$BASE_URL/health")
if ! echo "$HEALTH_RESPONSE" | jq -e '.status == "ok"' > /dev/null 2>&1; then
    echo "Error: Health check failed"
    echo "Response: $HEALTH_RESPONSE"
    exit 1
fi
echo "  ✓ Health check passed"

# Check VPN certificates directory
echo
echo "Checking VPN certificates..."
if ! podman exec nethsecurity-pod-vpn test -d /etc/openvpn/pki; then
    echo "Error: VPN PKI directory not found"
    exit 1
fi
echo "  ✓ VPN PKI directory exists"

# Check database connectivity
echo
echo "Testing database connectivity..."
if ! podman exec nethsecurity-pod-db pg_isready -U report > /dev/null 2>&1; then
    echo "Error: Database is not ready"
    exit 1
fi
echo "  ✓ Database is ready"

echo
echo "=== All smoke tests passed! ==="
echo
echo "Stack is running and healthy:"
echo "  - VPN:   Running on port 1194 (UDP)"
echo "  - API:   http://localhost:5000"
echo "  - UI:    http://localhost:3000"
echo "  - Proxy: http://localhost:8080"
echo
echo "Run './dev.sh stop' to stop the stack"
