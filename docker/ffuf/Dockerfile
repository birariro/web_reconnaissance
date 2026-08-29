# ffuf — directory / content brute force.
FROM debian:12-slim
ARG TARGETARCH=arm64
ARG VERSION=2.1.0
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSL -o /tmp/t.tgz "https://github.com/ffuf/ffuf/releases/download/v${VERSION}/ffuf_${VERSION}_linux_${TARGETARCH}.tar.gz" \
    && tar xzf /tmp/t.tgz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf \
    && rm -rf /tmp/t.tgz /var/lib/apt/lists/* \
    && ffuf -V
CMD ["sleep", "infinity"]
