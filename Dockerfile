FROM golang:1.23.4-alpine as builder

WORKDIR /app

COPY . .

RUN go build -o main main.go


FROM alpine:latest as runner

WORKDIR /app

COPY --from=builder /app/main /app/main

EXPOSE 1881

CMD ["./main"]