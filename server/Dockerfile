# syntax=docker/dockerfile:1

FROM node:24-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json tsconfig.json ./
RUN npm ci

COPY src ./src
RUN npm run build

FROM node:24-alpine

RUN apk add --no-cache tini \
  && adduser -D -h /data dud \
  && mkdir -p /data \
  && chown -R dud:dud /data

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY package.json ./

ENV DUD_DATA_DIR=/data
ENV DUD_LISTEN_HOST=0.0.0.0
ENV DUD_LISTEN_PORT=8787

VOLUME ["/data"]
EXPOSE 8787

USER dud

ENTRYPOINT ["/sbin/tini", "--", "node", "dist/src/node-server.js"]
CMD []
