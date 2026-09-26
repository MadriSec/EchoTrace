FROM debian:buster-slim

ARG GROOVY_VERSION=4.0.0

ENV JAVA_HOME=/opt/java \
    GROOVY_HOME=/opt/groovy \
    PATH=/opt/java/bin:/opt/java/jre/bin:/opt/groovy/bin:$PATH

RUN set -eux; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid-until; \
    sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        procps \
        unzip \
        zlib1g; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /opt/java /opt/downloads; \
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse?project=jdk" \
        -o /opt/downloads/temurin8.tar.gz; \
    tar -xzf /opt/downloads/temurin8.tar.gz -C /opt/java --strip-components=1; \
    curl -fsSL "https://archive.apache.org/dist/groovy/${GROOVY_VERSION}/distribution/apache-groovy-binary-${GROOVY_VERSION}.zip" \
        -o /opt/downloads/groovy.zip; \
    unzip -q /opt/downloads/groovy.zip -d /opt; \
    mv "/opt/groovy-${GROOVY_VERSION}" "${GROOVY_HOME}"; \
    rm -rf /opt/downloads; \
    groupadd --system groovy; \
    useradd --system --gid groovy --home-dir /home/groovy --create-home --shell /usr/sbin/nologin groovy; \
    chown -R groovy:groovy "${GROOVY_HOME}" /home/groovy

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER groovy
WORKDIR /home/groovy

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["groovy-hold"]
