FROM golang:1.21 as builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o smad

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/smad /app/
COPY config.json /app

ENTRYPOINT ["./smad"]