// Command go-strip-comments prints a Go source file from stdin without its
// comments, in gofmt form. Two files print the same exactly when they differ
// only in comments and formatting.
//
// Build directives (//go: and // +build lines) select the code that compiles,
// so they print too. A file with a cgo preamble prints whole, because the
// comment before import "C" is C code.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strings"
)

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "go-strip-comments:", err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer) error {
	src, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	commented, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return err
	}
	for _, spec := range commented.Imports {
		if spec.Path.Value == `"C"` {
			_, err = out.Write(src)
			return err
		}
	}
	file, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return err
	}
	var code bytes.Buffer
	if err := format.Node(&code, fset, file); err != nil {
		return err
	}
	if _, err := out.Write(code.Bytes()); err != nil {
		return err
	}
	for _, group := range commented.Comments {
		for _, comment := range group.List {
			if strings.HasPrefix(comment.Text, "//go:") || strings.HasPrefix(comment.Text, "// +build") {
				if _, err := fmt.Fprintln(out, comment.Text); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
