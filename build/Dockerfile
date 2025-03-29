FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod tidy

COPY . .
RUN go build -o asset_discovery ./cmd/asset_discovery/main.go

# Runner stage
FROM alpine:3.21.3 AS deploy

RUN apk add --no-cache tzdata
ENV TZ=Asia/Tehran

WORKDIR /usr/share/siem/asset_discovery

COPY --from=builder /app/asset_discovery .

EXPOSE 2030
CMD ["./asset_discovery", "--config" , "/etc/siem/asset_discovery/config.json"]
