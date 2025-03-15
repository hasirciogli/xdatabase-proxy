FROM golang:1.23.4-alpine

WORKDIR /app

COPY . .

RUN go build -o main main.go

EXPOSE 1881

CMD ["./main"]