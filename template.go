package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"html/template"
)

//go:embed index.html
var indexHTML string

//go:embed copy.js
var copyJS string

// Hashed at startup so the CSP source can never drift from the inlined script.
var scriptCSPSource = func() string {
	sum := sha256.Sum256([]byte(copyJS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

var pageTemplate = template.Must(template.New("index.html").Funcs(template.FuncMap{
	"copyScript": func() template.JS { return template.JS(copyJS) },
}).Parse(indexHTML))
