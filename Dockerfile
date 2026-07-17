FROM python:3.12-slim

# iputils/iproute2: ARP table + ICMP support for discovery
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# raw ICMP sockets without running as root; data dir must be writable by the
# runtime user (named volumes inherit ownership from the image directory).
# setcap may fail on build filesystems that don't support file capabilities; that
# is tolerated because docker-compose grants cap_add: NET_RAW at runtime, which is
# what actually enables ping discovery. (If you run without NET_RAW, discovery is
# the only module affected — everything else works.)
RUN useradd -r -m monitor \
    && mkdir -p /app/data \
    && chown -R monitor:monitor /app/data \
    && { setcap cap_net_raw+ep "$(readlink -f "$(which python3)")" \
         || echo "WARN: setcap failed; ping discovery needs cap_add: NET_RAW at runtime"; }

USER monitor
VOLUME /app/data
ENTRYPOINT ["netbox-monitor"]
CMD ["--config", "/app/config.yaml"]
