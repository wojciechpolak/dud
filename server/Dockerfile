# syntax=docker/dockerfile:1

# pin: node 24-alpine
ARG NODE_DIGEST=sha256:f70403e87646dc51b45295f4b8b70cdad0b63d2297c4c9899119b03f7af7a6b3

FROM node:24-alpine@${NODE_DIGEST} AS builder

WORKDIR /app

COPY package.json package-lock.json tsconfig.json ./
RUN npm ci

COPY src ./src
RUN npm run build:server

FROM node:24-alpine@${NODE_DIGEST}

RUN apk add --no-cache tini \
  && adduser -D -h /data dud \
  && mkdir -p /data \
  && chown -R dud:dud /data

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist

ENV DUD_DATA_DIR=/data
ENV DUD_LISTEN_HOST=0.0.0.0
ENV DUD_LISTEN_PORT=8787

VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8787/v1/test').then((response) => process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))"]

USER dud

ENTRYPOINT ["/sbin/tini", "--", "node", "dist/src/node-server.js"]
CMD []
