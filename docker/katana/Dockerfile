# ProjectDiscovery katana — JS-aware active crawler.
FROM debian:12-slim
ARG TARGETARCH=arm64
ARG VERSION=1.7.0
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && curl -sSL -o /tmp/t.zip "https://github.com/projectdiscovery/katana/releases/download/v${VERSION}/katana_${VERSION}_linux_${TARGETARCH}.zip" \
    && unzip -o /tmp/t.zip katana -d /usr/local/bin && chmod +x /usr/local/bin/katana \
    && rm -rf /tmp/t.zip /var/lib/apt/lists/* \
    && katana -version
CMD ["sleep", "infinity"]
