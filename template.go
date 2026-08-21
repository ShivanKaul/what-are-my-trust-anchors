package main

import (
	_ "embed"
	"html/template"
)

//go:embed index.html
var indexHTML string

var pageTemplate = template.Must(template.New("index.html").Parse(indexHTML))
