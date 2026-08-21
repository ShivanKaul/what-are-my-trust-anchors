FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/what-are-my-trust-anchors .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/what-are-my-trust-anchors /usr/local/bin/what-are-my-trust-anchors
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/what-are-my-trust-anchors"]
