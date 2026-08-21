package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	trustAnchorsExtension    uint16 = 0xca34
	orderHashBytes                  = 8
	maxConcurrentConnections        = 64
	maxClientHelloBytes             = 64 << 10
	maxHTTPRequestBytes             = 32 << 10
)

type AnchorID struct {
	RawHex      string `json:"raw_hex"`
	RelativeOID string `json:"relative_oid,omitempty"`
	FullOID     string `json:"full_oid,omitempty"`
	DecodeError string `json:"decode_error,omitempty"`
}

type TrustAnchorsInfo struct {
	Present       bool       `json:"present"`
	ExtensionHex  string     `json:"extension_hex"`
	OrderHash     string     `json:"order_hash,omitempty"`
	DeclaredBytes int        `json:"declared_list_bytes"`
	Empty         bool       `json:"empty"`
	Anchors       []AnchorID `json:"anchors"`
	ParseError    string     `json:"parse_error,omitempty"`
}

func (t TrustAnchorsInfo) lines() []string {
	out := make([]string, 0, len(t.Anchors))
	for _, a := range t.Anchors {
		m := a.Metadata()
		if m.Name == "" {
			out = append(out, a.RelativeOID)
			continue
		}
		out = append(out, m.Operator+"\t"+m.Name)
	}
	return out
}

func (t TrustAnchorsInfo) OrderedList() string { return strings.Join(t.lines(), "\n") }

func (t TrustAnchorsInfo) SortedList() string {
	l := t.lines()
	sort.Strings(l)
	return strings.Join(l, "\n")
}

type ExtensionInfo struct {
	Type   uint16 `json:"type"`
	Hex    string `json:"hex"`
	Name   string `json:"name"`
	Length int    `json:"length"`
}

type ClientHelloInfo struct {
	SNI           string           `json:"sni,omitempty"`
	LegacyVersion string           `json:"legacy_version"`
	RecordBytes   int              `json:"captured_tls_record_bytes"`
	Extensions    []ExtensionInfo  `json:"extensions"`
	TrustAnchors  TrustAnchorsInfo `json:"trust_anchors"`
}

type replayConn struct {
	net.Conn
	replay *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.replay.Len() > 0 {
		return c.replay.Read(p)
	}
	return c.Conn.Read(p)
}

func main() {
	addr := flag.String("addr", ":8443", "TLS listen address")
	httpAddr := flag.String("http-addr", ":8080", "HTTP listen address for ACME validation")
	hostname := flag.String("hostname", envOr("TLS_HOSTNAME", "what-are-my-trust-anchors.fly.dev"), "hostname for automatic TLS certificates")
	cacheDir := flag.String("autocert-cache", envOr("AUTOCERT_CACHE", "/tmp/autocert"), "certificate cache directory")
	certFile := flag.String("cert", "", "TLS certificate PEM; disables automatic certificates when used with -key")
	keyFile := flag.String("key", "", "TLS private key PEM; disables automatic certificates when used with -cert")
	flag.Parse()

	tlsConfig, err := makeTLSConfig(*hostname, *httpAddr, *cacheDir, *certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening for raw TLS on %s", *addr)

	slots := make(chan struct{}, maxConcurrentConnections)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		select {
		case slots <- struct{}{}:
			go func(conn net.Conn) {
				defer func() { <-slots }()
				handleConn(conn, tlsConfig)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func makeTLSConfig(hostname, httpAddr, cacheDir, certFile, keyFile string) (*tls.Config, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("both -cert and -key are required for static TLS")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		}, nil
	}

	if hostname == "" {
		return nil, errors.New("-hostname or TLS_HOSTNAME is required when using automatic TLS")
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(hostname),
	}

	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+hostname+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           manager.HTTPHandler(redirect),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    maxHTTPRequestBytes,
	}
	go func() {
		log.Printf("serving ACME HTTP validation on %s for %s", httpAddr, hostname)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ACME HTTP server: %v", err)
		}
	}()

	config := manager.TLSConfig()
	config.MinVersion = tls.VersionTLS12
	config.NextProtos = []string{"http/1.1", acme.ALPNProto}
	return config, nil
}

func handleConn(conn net.Conn, tlsConfig *tls.Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	captured, info, err := captureClientHello(conn)
	if err != nil {
		log.Printf("client hello: %v", err)
		return
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	tlsConn := tls.Server(&replayConn{Conn: conn, replay: bytes.NewReader(captured)}, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake: %v", err)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	reader := bufio.NewReader(io.LimitReader(tlsConn, maxHTTPRequestBytes))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}

	var body []byte
	contentType := "text/html; charset=utf-8"
	status := "200 OK"

	switch req.URL.Path {
	case "/json":
		body, err = json.MarshalIndent(info, "", "  ")
		contentType = "application/json; charset=utf-8"
	case "/", "/index.html":
		var b bytes.Buffer
		err = pageTemplate.Execute(&b, info)
		body = b.Bytes()
	case "/copy.js":
		body = []byte(copyJS)
		contentType = "text/javascript; charset=utf-8"
	default:
		status = "404 Not Found"
		body = []byte("not found\n")
		contentType = "text/plain; charset=utf-8"
	}
	if err != nil {
		status = "500 Internal Server Error"
		body = []byte("render error\n")
		contentType = "text/plain; charset=utf-8"
	}

	writer := bufio.NewWriter(tlsConn)
	fmt.Fprintf(writer, "HTTP/1.1 %s\r\n", status)
	fmt.Fprintf(writer, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(writer, "Content-Length: %d\r\n", len(body))
	fmt.Fprint(writer, "Cache-Control: no-store\r\n")
	fmt.Fprint(writer, "Connection: close\r\n")
	fmt.Fprint(writer, "Referrer-Policy: no-referrer\r\n")
	fmt.Fprint(writer, "X-Content-Type-Options: nosniff\r\n")
	fmt.Fprint(writer, "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\n")
	fmt.Fprint(writer, "\r\n")
	_, _ = writer.Write(body)
	_ = writer.Flush()
}

func captureClientHello(conn net.Conn) ([]byte, ClientHelloInfo, error) {
	var captured bytes.Buffer
	var handshake bytes.Buffer
	var expected int

	for captured.Len() < maxClientHelloBytes {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, ClientHelloInfo{}, err
		}
		length := int(header[3])<<8 | int(header[4])
		if length <= 0 || length > 18432 {
			return nil, ClientHelloInfo{}, fmt.Errorf("invalid TLS record length %d", length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, ClientHelloInfo{}, err
		}
		captured.Write(header)
		captured.Write(payload)

		if header[0] != 22 {
			return nil, ClientHelloInfo{}, fmt.Errorf("expected TLS handshake record, got content type %d", header[0])
		}
		handshake.Write(payload)

		if expected == 0 && handshake.Len() >= 4 {
			h := handshake.Bytes()
			if h[0] != 1 {
				return nil, ClientHelloInfo{}, fmt.Errorf("expected ClientHello, got handshake type %d", h[0])
			}
			expected = 4 + int(h[1])<<16 + int(h[2])<<8 + int(h[3])
			if expected > maxClientHelloBytes {
				return nil, ClientHelloInfo{}, errors.New("ClientHello too large")
			}
		}
		if expected > 0 && handshake.Len() >= expected {
			info, err := parseClientHello(handshake.Bytes()[:expected])
			info.RecordBytes = captured.Len()
			return captured.Bytes(), info, err
		}
	}
	return nil, ClientHelloInfo{}, errors.New("ClientHello exceeded capture limit")
}

func parseClientHello(msg []byte) (ClientHelloInfo, error) {
	var out ClientHelloInfo
	out.TrustAnchors.Anchors = []AnchorID{}

	if len(msg) < 4 || msg[0] != 1 {
		return out, errors.New("not a ClientHello")
	}
	body := msg[4:]
	if len(body) < 34 {
		return out, errors.New("truncated ClientHello")
	}

	out.LegacyVersion = fmt.Sprintf("0x%02x%02x", body[0], body[1])
	p := 34

	if p >= len(body) {
		return out, errors.New("missing session ID")
	}
	sessionLen := int(body[p])
	p++
	if p+sessionLen > len(body) {
		return out, errors.New("truncated session ID")
	}
	p += sessionLen

	cipherSuites, next, err := readU16Vector(body, p)
	if err != nil || len(cipherSuites)%2 != 0 {
		return out, errors.New("invalid cipher suites")
	}
	p = next

	if p >= len(body) {
		return out, errors.New("missing compression methods")
	}
	compressionLen := int(body[p])
	p++
	if p+compressionLen > len(body) {
		return out, errors.New("truncated compression methods")
	}
	p += compressionLen

	extBytes, _, err := readU16Vector(body, p)
	if err != nil {
		return out, errors.New("invalid extensions vector")
	}

	for q := 0; q < len(extBytes); {
		if q+4 > len(extBytes) {
			return out, errors.New("truncated extension header")
		}
		typ := uint16(extBytes[q])<<8 | uint16(extBytes[q+1])
		n := int(extBytes[q+2])<<8 | int(extBytes[q+3])
		q += 4
		if q+n > len(extBytes) {
			return out, fmt.Errorf("truncated extension 0x%04x", typ)
		}
		data := extBytes[q : q+n]
		q += n

		out.Extensions = append(out.Extensions, ExtensionInfo{
			Type:   typ,
			Hex:    fmt.Sprintf("0x%04x", typ),
			Name:   extensionName(typ),
			Length: len(data),
		})

		switch typ {
		case 0:
			out.SNI = parseSNI(data)
		case trustAnchorsExtension:
			out.TrustAnchors = parseTrustAnchors(data)
		}
	}
	return out, nil
}

func parseTrustAnchors(data []byte) TrustAnchorsInfo {
	out := TrustAnchorsInfo{Present: true, ExtensionHex: hex.EncodeToString(data), Anchors: []AnchorID{}}
	if len(data) < 2 {
		out.ParseError = "missing uint16 list length"
		return out
	}
	declared := int(data[0])<<8 | int(data[1])
	out.DeclaredBytes = declared
	if declared != len(data)-2 {
		out.ParseError = fmt.Sprintf("list length says %d bytes, extension contains %d", declared, len(data)-2)
		return out
	}
	out.Empty = declared == 0
	if !out.Empty {
		sum := sha256.Sum256(data)
		out.OrderHash = hex.EncodeToString(sum[:orderHashBytes])
	}

	list := data[2:]
	for p := 0; p < len(list); {
		n := int(list[p])
		p++
		if n == 0 {
			out.ParseError = "zero-length TrustAnchorID"
			return out
		}
		if p+n > len(list) {
			out.ParseError = "truncated TrustAnchorID"
			return out
		}
		raw := list[p : p+n]
		p += n
		id := AnchorID{RawHex: hex.EncodeToString(raw)}
		components, err := decodeRelativeOID(raw)
		if err != nil {
			id.DecodeError = err.Error()
		} else {
			id.RelativeOID = components
			id.FullOID = "1.3.6.1.4.1." + components
		}
		out.Anchors = append(out.Anchors, id)
	}
	return out
}

func decodeRelativeOID(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("empty relative OID")
	}
	var components []string
	for p := 0; p < len(raw); {
		start := p
		var v uint64
		for {
			if p >= len(raw) {
				return "", errors.New("unterminated base-128 OID component")
			}
			b := raw[p]
			p++
			if p-start > 10 {
				return "", errors.New("OID component too large")
			}
			if p-start == 1 && b == 0x80 {
				return "", errors.New("non-minimal OID component")
			}
			if v > (^uint64(0) >> 7) {
				return "", errors.New("OID component overflows uint64")
			}
			v = (v << 7) | uint64(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
		components = append(components, strconv.FormatUint(v, 10))
	}
	return strings.Join(components, "."), nil
}

func parseSNI(data []byte) string {
	list, _, err := readU16Vector(data, 0)
	if err != nil {
		return ""
	}
	for p := 0; p+3 <= len(list); {
		typ := list[p]
		n := int(list[p+1])<<8 | int(list[p+2])
		p += 3
		if p+n > len(list) {
			return ""
		}
		if typ == 0 {
			return string(list[p : p+n])
		}
		p += n
	}
	return ""
}

func readU16Vector(b []byte, p int) ([]byte, int, error) {
	if p+2 > len(b) {
		return nil, p, io.ErrUnexpectedEOF
	}
	n := int(b[p])<<8 | int(b[p+1])
	p += 2
	if p+n > len(b) {
		return nil, p, io.ErrUnexpectedEOF
	}
	return b[p : p+n], p + n, nil
}

func extensionName(typ uint16) string {
	names := map[uint16]string{
		0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
		13: "signature_algorithms", 16: "alpn", 18: "signed_certificate_timestamp", 21: "padding",
		23: "extended_master_secret", 27: "compress_certificate", 35: "session_ticket", 41: "pre_shared_key",
		42: "early_data", 43: "supported_versions", 45: "psk_key_exchange_modes", 47: "certificate_authorities",
		50: "signature_algorithms_cert", 51: "key_share", 57: "quic_transport_parameters",
		17513: "application_settings_old", 17613: "application_settings", 65037: "encrypted_client_hello",
		trustAnchorsExtension: "trust_anchors (draft/experimental)",
	}
	if name, ok := names[typ]; ok {
		return name
	}
	if isGREASE(typ) {
		return "GREASE"
	}
	return "unknown"
}

func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && byte(v)&0x0f == 0x0a
}
