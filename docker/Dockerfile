FROM golang:1.25 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY models/*.go ./models/
COPY ldap/*.go ./ldap/

RUN CGO_ENABLED=0 GOOS=linux go build -o smad

FROM alpine:3.23
WORKDIR /app
RUN apk update && apk upgrade && addgroup -S smadgrp && adduser -S smadusr -G smadgrp
COPY --from=builder /app/smad /app/
COPY --chown=smadusr:smadgrp configs/config.json.example /app/configs/config.json
COPY --chown=smadusr:smadgrp configs/users.json.example /app/configs/users.json
COPY --chown=smadusr:smadgrp configs/groups.json.example /app/configs/groups.json
USER smadusr
EXPOSE 1389

ENTRYPOINT ["./smad"]