# What Are My Trust Anchors?

Small Go HTTPS server that reads the raw TLS `ClientHello` and reports Chromium/BoringSSL's experimental `trust_anchors` extension (`0xca34`).

- `/` shows Trust Anchor IDs, known certificate names, and the ordered-payload hash.
- `/json` returns the parsed `ClientHello`.
- Port 443 is raw TCP passthrough; the app (hosted on [Fly.io](https://fly.io/)) terminates TLS so it can inspect the original handshake.

```bash
./dev-cert.sh
go test ./...
go run . -cert cert.pem -key key.pem
```
