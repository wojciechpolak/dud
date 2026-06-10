# pin: debian stable-slim
ARG DEBIAN_DIGEST=sha256:5012d0517aa0075a7150a45aae67586641e898913b7af3b08228108565b5f90c

FROM debian:stable-slim@${DEBIAN_DIGEST} AS build-base

ENV DEBIAN_FRONTEND=noninteractive
ENV OPENSSL_PREFIX=/opt/ech-openssl
ENV CURL_PREFIX=/opt/ech-curl
ENV AGE_PREFIX=/opt/age

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    git \
    golang-go \
    libtool \
    make \
    perl \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

FROM build-base AS client-builder

# Version from the repo root package.json; the build context is client/
# only, so it has to come in as a build arg.
ARG DUD_VERSION=dev

WORKDIR /client

COPY go.mod ./
COPY cmd ./cmd

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${DUD_VERSION}" -o /usr/local/bin/dud ./cmd/dud

FROM build-base AS builder

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

# pin: curl curl-8_20_0
RUN git init curl \
  && git -C curl remote add origin https://github.com/curl/curl.git \
  && git -C curl fetch --depth 1 origin a05f34973e6c4bb629d018f7cb51487be1c904d8 \
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

# pin: age v1.3.1
RUN git init age \
  && git -C age remote add origin https://github.com/FiloSottile/age.git \
  && git -C age fetch --depth 1 origin b8564adb6d58329b8a3e267360ca2b0abc4efe1d \
  && git -C age checkout FETCH_HEAD \
  && cd age \
  && GOBIN="$AGE_PREFIX/bin" go install ./cmd/...

FROM debian:stable-slim@${DEBIAN_DIGEST}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    findutils \
    git \
    qrencode \
    tar \
    tini \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 1000 -s /sbin/nologin -d /work dud

WORKDIR /work

COPY --from=builder /opt/age/bin/age /usr/local/bin/age
COPY --from=builder /opt/age/bin/age-keygen /usr/local/bin/age-keygen
COPY --from=builder /opt/ech-curl/bin/curl /usr/local/bin/curl
COPY --from=client-builder /usr/local/bin/dud /usr/local/bin/dud

RUN chmod +x /usr/local/bin/dud \
  && chown dud:dud /work

# Run as non-root. Mount /tmp as tmpfs at runtime to keep sensitive
# intermediate files off the overlay filesystem:
#   docker run --tmpfs /tmp:rw,noexec,nosuid,size=128m ...
USER dud

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/dud"]
CMD []
