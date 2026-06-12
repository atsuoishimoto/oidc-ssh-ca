package main

import (
	"flag"
	"os"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/audit"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/issuer"
	lambdatransport "github.com/atsuoishimoto/oidc-ssh-ca/internal/lambda"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/oidc"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/server"
)

// EnvConfig overrides the policy path in environments where flags are
// awkward (Lambda).
const EnvConfig = "OIDC_SSH_CA_CONFIG"

// runningInLambda reports whether the process was started by the AWS
// Lambda runtime (provided.al2023 sets AWS_LAMBDA_RUNTIME_API).
func runningInLambda() bool {
	return os.Getenv("AWS_LAMBDA_RUNTIME_API") != ""
}

// cmdLambda serves Function URL events. The policy is loaded once at
// cold start; there is no reload — updates are deployed as a new zip.
// The CA key comes from OIDC_SSH_CA_KEY (or OIDC_SSH_CA_KEY_FILE).
func cmdLambda(args []string) error {
	fs := flag.NewFlagSet("lambda", flag.ExitOnError)
	configPath := fs.String("config", "", "path to policy.yaml (default $"+EnvConfig+" or ./policy.yaml)")
	fs.Parse(args)

	path := *configPath
	if path == "" {
		path = os.Getenv(EnvConfig)
	}
	if path == "" {
		// The zip is unpacked into the working directory (/var/task).
		path = "policy.yaml"
	}

	// Fail fast: a bad policy or CA key fails the cold start.
	pol, err := policy.Load(path)
	if err != nil {
		return err
	}
	signer, err := issuer.LoadCAKey("")
	if err != nil {
		return err
	}

	log := audit.New()
	srv := server.New(pol, signer, oidc.NewRemoteVerifier(), log)

	log.Info("starting lambda",
		"version", version,
		"ca_fingerprint", issuer.Fingerprint(signer),
		"policy", path,
		"rules", len(pol.Rules),
		"disabled", pol.Disabled,
	)

	lambdatransport.Start(srv)
	return nil
}
