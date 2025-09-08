FROM golang:1.25 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY models/*.go ./models/
COPY ldap/*.go ./ldap/

RUN CGO_ENABLED=0 GOOS=linux go build -o smad

FROM alpine:3.22
WORKDIR /app
RUN addgroup -S smadgrp && adduser -S smadusr -G smadgrp
COPY --from=builder /app/smad /app/
COPY configs/config.json.example /app/configs/config.json
COPY configs/users.json.example /app/configs/users.json
COPY configs/groups.json.example /app/configs/groups.json
USER smadusr

ENTRYPOINT ["./smad"]