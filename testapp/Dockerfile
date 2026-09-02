ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/testapp ./testapp

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/testapp /testapp

ENTRYPOINT ["/testapp"]
