package main

import (
	"embed"
	"html/template"
)

//go:embed index.html
var templateFiles embed.FS

func init() {
	pageTemplate = template.Must(template.ParseFS(templateFiles, "index.html"))
}
