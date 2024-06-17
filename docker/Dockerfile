FROM golang:1.22 as builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o smad

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/smad /app/
COPY config.example.json /app/config.json

ENTRYPOINT ["./smad"]