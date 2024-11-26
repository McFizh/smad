FROM golang:1.23 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o smad

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/smad /app/
COPY configs/config.json.example /app/configs/config.json
COPY configs/users.json.example /app/configs/users.json
COPY configs/groups.json.example /app/configs/groups.json

ENTRYPOINT ["./smad"]