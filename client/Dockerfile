# pin: debian stable-slim
ARG DEBIAN_DIGEST=sha256:5012d0517aa0075a7150a45aae67586641e898913b7af3b08228108565b5f90c

FROM debian:stable-slim@${DEBIAN_DIGEST} AS build-base

ENV DEBIAN_FRONTEND=noninteractive
ENV AGE_PREFIX=/opt/age

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    golang-go \
  && rm -rf /var/lib/apt/lists/*

FROM build-base AS client-builder

# Version from the repo root package.json; the build context is client/
# only, so it has to come in as a build arg.
ARG DUD_VERSION=dev

WORKDIR /client

COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${DUD_VERSION}" -o /usr/local/bin/dud ./cmd/dud

FROM build-base AS builder

WORKDIR /build

# pin: age v1.3.1
# pin-transitive: filippo.io/hpke v0.4.0
#   Locked and hash-verified by age's own go.sum at the commit pinned below, so
#   the build is already deterministic. Recorded here because it is otherwise
#   invisible: it provides the MLKEM768-X25519 hybrid KEM that carries v2
#   payload confidentiality and the pairing key agreement, so it needs to appear
#   in vulnerability triage and the SBOM. Re-check this line when bumping age.
RUN git init age \
  && git -C age remote add origin https://github.com/FiloSottile/age.git \
  && git -C age fetch --depth 1 origin b8564adb6d58329b8a3e267360ca2b0abc4efe1d \
  && git -C age checkout FETCH_HEAD

WORKDIR /build/age

RUN GOBIN="$AGE_PREFIX/bin" go install ./cmd/...

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
COPY --from=client-builder /usr/local/bin/dud /usr/local/bin/dud

RUN chmod +x /usr/local/bin/dud \
  && chown dud:dud /work

# Run as non-root. Mount /tmp as tmpfs at runtime to keep sensitive
# intermediate files off the overlay filesystem:
#   docker run --tmpfs /tmp:rw,noexec,nosuid,size=128m ...
USER dud

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/dud"]
CMD []
