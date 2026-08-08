package web

import (
	"embed"
	"io/fs"
	"log"
)

//go:embed static
var staticFS embed.FS

var StaticFS fs.FS

func init() {
	var err error
	StaticFS, err = fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}
}
