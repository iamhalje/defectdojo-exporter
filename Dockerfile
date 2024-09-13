FROM golang:1.22.5-alpine AS builder
WORKDIR /app

COPY . ./

WORKDIR /app/cmd/defectdojo-exporter

RUN apk add --no-cache binutils \
    && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o defectdojo-exporter main.go \
    && strip /app/cmd/defectdojo-exporter/defectdojo-exporter

FROM alpine:3.20

COPY --from=builder /app/cmd/defectdojo-exporter/defectdojo-exporter /usr/local/bin/defectdojo-exporter
