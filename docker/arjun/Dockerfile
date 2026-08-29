# arjun — hidden HTTP parameter discovery (Python).
FROM python:3.12-slim
ARG VERSION=2.2.7
RUN pip install --no-cache-dir "arjun==${VERSION}" && arjun --help >/dev/null
CMD ["sleep", "infinity"]
