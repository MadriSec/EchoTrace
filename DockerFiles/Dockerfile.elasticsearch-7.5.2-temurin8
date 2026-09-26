FROM debian:buster-slim

ARG ES_VERSION=7.5.2

ENV JAVA_HOME=/opt/java \
    ES_JAVA_HOME=/opt/java \
    ES_HOME=/opt/elasticsearch \
    PATH=/opt/java/bin:/opt/java/jre/bin:/opt/elasticsearch/bin:$PATH

RUN set -eux; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid-until; \
    sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        libatomic1 \
        libstdc++6 \
        procps \
        tar \
        zlib1g; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /opt/java /opt/es-download; \
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse?project=jdk" \
        -o /opt/es-download/temurin8.tar.gz; \
    tar -xzf /opt/es-download/temurin8.tar.gz -C /opt/java --strip-components=1; \
    curl -fsSL "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz" \
        -o /opt/es-download/elasticsearch.tar.gz; \
    tar -xzf /opt/es-download/elasticsearch.tar.gz -C /opt; \
    mv "/opt/elasticsearch-${ES_VERSION}" "${ES_HOME}"; \
    rm -rf "${ES_HOME}/jdk" /opt/es-download; \
    groupadd --system elasticsearch; \
    useradd --system --gid elasticsearch --home-dir "${ES_HOME}" --shell /usr/sbin/nologin elasticsearch; \
    mkdir -p /usr/share/elasticsearch/data /usr/share/elasticsearch/logs; \
    chown -R elasticsearch:elasticsearch "${ES_HOME}" /usr/share/elasticsearch

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER elasticsearch
WORKDIR /opt/elasticsearch

EXPOSE 9200 9300

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["elasticsearch"]
