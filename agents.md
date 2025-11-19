This repository contains the backend services for the NethSecurity Controller, a centralized management system for NethSecurity firewall instances. It includes the Go API, VPN server, and proxy configuration.

**IMPORTANT**: The web UI (frontend) code is located in a separate repository: [NethServer/nethsecurity-ui](https://github.com/NethServer/nethsecurity-ui)

## Dev Environment Setup
The development environment is managed by Podman and the `dev.sh` script. This script will set up a pod containing all necessary services, including the API, VPN, UI, proxy, and a database.

1.  **Create Network Device**: Before starting, you must create a `tunsec` network device with root privileges. This only needs to be done once.
    ```bash
    sudo ip tuntap add dev tunsec mod tun
    sudo ip addr add 172.21.0.1/16 dev tunsec
    sudo ip link set dev tunsec up
    ```

2.  **Start Environment**: Run the `start` command to create and start the Podman pod. This also generates an `api.env` file with the necessary environment variables for the API service.
    ```bash
    ./dev.sh start
    ```

3.  **Stop Environment**: Run the `stop` command to stop and remove the Podman pod when you are finished.
    ```bash
    ./dev.sh stop
    ```

## Build Instructions
- The `build.sh` script uses `buildah` to build the container images for all services.
- Run the script to create all images locally:
  ```bash
  ./build.sh
  ```

## Testing Instructions
- Do not validate tests if database is not running: the datbase is required
- The backend tests are written in Go.
- Before running the tests, ensure that the TimescaleDB database is running. You can use Podman to start a TimescaleDB container:
  ```bash
  podman run --rm -d --name timescaledb -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_USER=report timescale/timescaledb-ha:pg17
  # Wait for DB to be ready
  for i in {1..30}; do
    podman exec timescaledb pg_isready -U report && break
    sleep 1
  done
  ```
- To run the entire API test suite, navigate to the `api` directory and use `go test`:
  ```bash
  cd api && go test ./...
  ```
- Please add or update tests for any code you change.
- Stop the TimescaleDB container after testing:
  ```bash
  podman stop timescaledb
  ```

## PR & Commit Instructions
- This project follows the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.
- Please format your commit messages accordingly. The scope of the commit should be one of the services (`api`, `vpn`, `ui`, `proxy`).
- **Good commit message examples**:
  - `feat(api): add endpoint for user preferences`
  - `fix(vpn): resolve authentication handshake failure`
  - `docs(api): update documentation for /status endpoint`
