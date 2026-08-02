# syntax=docker/dockerfile:1
FROM node:20-alpine AS frontend
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm ci || npm install
COPY web/ .
RUN npm run build

FROM golang:1.23-alpine AS backend
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/substore ./cmd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
ENV SUB_STORE_DATA_PATH=/app/data \
    SUB_STORE_FRONTEND_PATH=/app/web/dist
COPY --from=backend /out/substore /app/substore
COPY --from=frontend /web/dist /app/web/dist
EXPOSE 3000
VOLUME ["/app/data"]
ENTRYPOINT ["/app/substore"]
