// Command oidc-ssh-ca is a small SSH certificate authority that issues
// short-lived OpenSSH user certificates to OIDC-authenticated callers.
package main

import (
	"fmt"
	"os"
)

// version is the released version baked into the binary; GoReleaser
// overrides it at build time via -ldflags.
var version = "0.4.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "check-config":
		err = cmdCheckConfig(os.Args[2:])
	case "explain":
		err = cmdExplain(os.Args[2:])
	case "print-ca-pub":
		err = cmdPrintCAPub(os.Args[2:])
	case "version", "--version", "-v", "-V":
		fmt.Println("oidc-ssh-ca", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `oidc-ssh-ca - issue short-lived OpenSSH user certificates from OIDC identities

Usage:
  oidc-ssh-ca serve --config policy.yaml [--listen :8080] [--ca-key-file PATH]
  oidc-ssh-ca check-config policy.yaml
  oidc-ssh-ca explain --policy policy.yaml --claims claims.json
  oidc-ssh-ca print-ca-pub [--ca-key-file PATH]
  oidc-ssh-ca version            (also: --version, -v)

The CA private key is configured by exactly one of:
  --ca-key-file PATH        path to an OpenSSH ed25519 private key (0600)
  OIDC_SSH_CA_KEY_FILE      same, via environment variable
  OIDC_SSH_CA_KEY           the private key itself, via environment variable
`)
}
