package main

import (
	"flag"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/issuer"
)

// cmdPrintCAPub prints the CA public key in authorized_keys format, for
// distribution to servers as TrustedUserCAKeys.
func cmdPrintCAPub(args []string) error {
	fs := flag.NewFlagSet("print-ca-pub", flag.ExitOnError)
	caKeyFile := fs.String("ca-key-file", "", "path to the CA private key")
	fs.Parse(args)

	signer, err := issuer.LoadCAKey(*caKeyFile)
	if err != nil {
		return err
	}
	fmt.Print(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return nil
}
