FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
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
