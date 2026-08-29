# gau — historical URLs from public archives (passive).
FROM debian:12-slim
ARG TARGETARCH=arm64
ARG VERSION=2.2.4
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSL -o /tmp/t.tgz "https://github.com/lc/gau/releases/download/v${VERSION}/gau_${VERSION}_linux_${TARGETARCH}.tar.gz" \
    && tar xzf /tmp/t.tgz -C /usr/local/bin gau && chmod +x /usr/local/bin/gau \
    && rm -rf /tmp/t.tgz /var/lib/apt/lists/* \
    && gau --version
CMD ["sleep", "infinity"]
