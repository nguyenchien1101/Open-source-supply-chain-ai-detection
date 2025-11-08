# 1. Base như bạn đang dùng
FROM debian:bookworm-slim

# 2. Cài tools cơ bản + jq + python3 (tùy, nhưng nên có)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      xz-utils \
      git \
      docker.io \
      jq \
      python3 \
 && rm -rf /var/lib/apt/lists/*

# 3. Cài Snyk CLI (Linux standalone)
# Có thể ghim version nếu muốn: https://static.snyk.io/cli/v1.1296.0/snyk-linux
RUN curl -fsSL https://static.snyk.io/cli/latest/snyk-linux -o /usr/local/bin/snyk \
 && chmod +x /usr/local/bin/snyk

# 4. Thư mục làm việc
WORKDIR /work

# 5. Biến env cho Snyk (giống bạn)
ENV SNYK_CFG_DIR=/root/.config/snyk

# 6. Mặc định gọi "snyk"
ENTRYPOINT ["snyk"]
CMD ["--help"]

