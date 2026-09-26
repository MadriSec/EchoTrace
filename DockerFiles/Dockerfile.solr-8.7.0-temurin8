FROM debian:buster-slim

ARG SOLR_VERSION=8.7.0

ENV JAVA_HOME=/opt/java \
    SOLR_HOME=/var/solr/data \
    SOLR_INSTALL_DIR=/opt/solr \
    PATH=/opt/java/bin:/opt/java/jre/bin:/opt/solr/bin:$PATH

RUN set -eux; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid-until; \
    sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        lsof \
        procps \
        tar \
        zlib1g; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /opt/java /opt/downloads; \
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse?project=jdk" \
        -o /opt/downloads/temurin8.tar.gz; \
    tar -xzf /opt/downloads/temurin8.tar.gz -C /opt/java --strip-components=1; \
    curl -fsSL "https://archive.apache.org/dist/lucene/solr/${SOLR_VERSION}/solr-${SOLR_VERSION}.tgz" \
        -o /opt/downloads/solr.tgz; \
    tar -xzf /opt/downloads/solr.tgz -C /opt; \
    mv "/opt/solr-${SOLR_VERSION}" "${SOLR_INSTALL_DIR}"; \
    rm -rf /opt/downloads; \
    groupadd --system solr; \
    useradd --system --gid solr --home-dir /var/solr --shell /usr/sbin/nologin solr; \
    mkdir -p /var/solr/data /var/solr/logs; \
    cp -a "${SOLR_INSTALL_DIR}/server/solr/." /var/solr/data/; \
    chown -R solr:solr "${SOLR_INSTALL_DIR}" /var/solr

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER solr
WORKDIR /opt/solr

EXPOSE 8983

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["solr-foreground"]
