FROM golang:1.26.10-alpine3.24@sha256:5cb67f19c5e7994dcb80c074f7cfca8aeeada45bbdca035f73df269cefdcce61 AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go vet ./... && go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/what-are-my-trust-anchors .

FROM alpine:3.24.3@sha256:b3413572228e34bd1c9245f5565e6cd127005655e8a7899aef33d8e83255c9e6
RUN addgroup -S app && adduser -S -D -H -G app app && mkdir -p /data
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/what-are-my-trust-anchors /usr/local/bin/what-are-my-trust-anchors
COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
