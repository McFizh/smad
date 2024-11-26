FROM golang:1.23 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o smad

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/smad /app/
COPY config.json.example /app/config.json
COPY users.json.example /app/users.json
COPY groups.json.example /app/groups.json

ENTRYPOINT ["./smad"]