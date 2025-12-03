ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --no-cache git openssl binutils

WORKDIR /src

COPY . .

ARG APP_NAME
ARG PKG_PREFIX
ARG GO_BUILDINFO

ENV GO_LDFLAGS="-s -w ${GO_BUILDINFO}"

RUN CGO_ENABLED=0 go build -ldflags "${GO_LDFLAGS}" -o /out/${APP_NAME} ${PKG_PREFIX}/cmd

FROM alpine:latest AS export-stage

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/ ./

ENTRYPOINT ["./defectdojo-exporter"]
