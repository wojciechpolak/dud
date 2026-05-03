# pin: debian stable-slim
ARG DEBIAN_DIGEST=sha256:e51bfcd2226c480a5416730e0fa2c40df28b0da5ff562fc465202feeef2f1116

FROM debian:stable-slim@${DEBIAN_DIGEST} AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV OPENSSL_PREFIX=/opt/ech-openssl
ENV CURL_PREFIX=/opt/ech-curl

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    git \
    libtool \
    make \
    perl \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# pin: openssl openssl-4.0.0
RUN git init openssl \
  && git -C openssl remote add origin https://github.com/openssl/openssl.git \
  && git -C openssl fetch --depth 1 origin 11b7b6ea3b65a584e1d31408ed1bdb139465cffd \
  && git -C openssl checkout FETCH_HEAD \
  && cd openssl \
  && ./config no-shared --libdir=lib --prefix="$OPENSSL_PREFIX" \
  && make -j"$(nproc)" \
  && make install_sw

# pin: curl curl-8_19_0
RUN git init curl \
  && git -C curl remote add origin https://github.com/curl/curl.git \
  && git -C curl fetch --depth 1 origin 8c908d2d0a6d32abdedda2c52e90bd56ec76c24d \
  && git -C curl checkout FETCH_HEAD \
  && cd curl \
  && autoreconf -fi \
  && ./configure \
    --prefix="$CURL_PREFIX" \
    --with-openssl="$OPENSSL_PREFIX" \
    --enable-ech \
    --disable-shared \
    --enable-static \
    --without-brotli \
    --without-libidn2 \
    --without-libpsl \
    --without-libssh2 \
    --without-nghttp2 \
    --without-nghttp3 \
    --without-ngtcp2 \
    --without-zstd \
    --disable-dict \
    --disable-file \
    --disable-ftp \
    --disable-gopher \
    --disable-imap \
    --disable-ipfs \
    --disable-ldap \
    --disable-ldaps \
    --disable-manual \
    --disable-mqtt \
    --disable-pop3 \
    --disable-rtsp \
    --disable-smb \
    --disable-smtp \
    --disable-telnet \
    --disable-tftp \
  && make -j"$(nproc)" \
  && make install

FROM debian:stable-slim@${DEBIAN_DIGEST}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    age \
    ca-certificates \
    qrencode \
    tini \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 1000 -s /sbin/nologin -d /work dud

WORKDIR /work

COPY --from=builder /opt/ech-curl/bin/curl /usr/local/bin/curl
COPY entrypoint.sh /usr/local/bin/dud

RUN chmod +x /usr/local/bin/dud \
  && chown dud:dud /work

# Run as non-root. Mount /tmp as tmpfs at runtime to keep sensitive
# intermediate files off the overlay filesystem:
#   docker run --tmpfs /tmp:rw,noexec,nosuid,size=128m ...
USER dud

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/dud"]
CMD []
