// Command c8s-allowlist-canonical prints the canonical bytes of a c8s
// allowlist document, exactly as the pinned c8s release computes them.
//
// CDS compares allowlists by these bytes. The release allowlist must be in
// this form, so that its SHA-256 in the signed release manifest equals the
// digest of the document CDS serves.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: c8s-allowlist-canonical <allowlist.json|->")
		os.Exit(2)
	}
	var data []byte
	var err error
	if os.Args[1] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	document, err := allowlist.ParseJSON(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	canonical, err := document.Canonical()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(canonical)
}
