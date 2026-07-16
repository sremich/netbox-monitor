FROM python:3.12-slim

# iputils/iproute2: ARP table + ICMP support for discovery
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# raw ICMP sockets without running as root
RUN useradd -r -m monitor \
    && setcap cap_net_raw+ep "$(readlink -f "$(which python3)")" || true

USER monitor
VOLUME /app/data
ENTRYPOINT ["netbox-monitor"]
CMD ["--config", "/app/config.yaml"]
