# ProjectDiscovery httpx — HTTP probing, tech detect, response headers, TLS grab.
FROM debian:12-slim
ARG TARGETARCH=arm64
ARG VERSION=1.10.0
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && curl -sSL -o /tmp/t.zip "https://github.com/projectdiscovery/httpx/releases/download/v${VERSION}/httpx_${VERSION}_linux_${TARGETARCH}.zip" \
    && unzip -o /tmp/t.zip httpx -d /usr/local/bin && chmod +x /usr/local/bin/httpx \
    && rm -rf /tmp/t.zip /var/lib/apt/lists/* \
    && httpx -version
CMD ["sleep", "infinity"]
