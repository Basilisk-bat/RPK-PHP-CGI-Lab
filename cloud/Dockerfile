FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential ca-certificates libxml2-dev libsqlite3-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY php-source.tar.gz /tmp/php-source.tar.gz
RUN mkdir /src \
    && tar -xzf /tmp/php-source.tar.gz -C /src --strip-components=1 \
    && cd /src \
    && ./configure --disable-all --enable-cli --enable-cgi --enable-session --without-pear \
    && make -j2 \
    && test -x /src/sapi/cli/php \
    && test -x /src/sapi/cgi/php-cgi \
    && rm /tmp/php-source.tar.gz

COPY src/ /opt/lab/
COPY run.sh /opt/lab/run.sh
RUN useradd --uid 10001 --create-home lab \
    && chmod 0555 /opt/lab/run.sh \
    && mkdir /work /results \
    && chown lab:lab /work /results

USER 10001:10001
WORKDIR /work
CMD ["/opt/lab/run.sh"]
