FROM golang:1.23.4-alpine as builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -o main apps/proxy/main.go

FROM alpine:latest as runner

WORKDIR /app

COPY --from=builder /app/main /app/main

CMD ["./main"]
