package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atsuoishimoto/oidc-ssh-ca/internal/audit"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/issuer"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/oidc"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/policy"
	"github.com/atsuoishimoto/oidc-ssh-ca/internal/server"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "path to policy.yaml (required)")
	listen := fs.String("listen", ":8080", "listen address")
	caKeyFile := fs.String("ca-key-file", "", "path to the CA private key")
	skipKeyPermCheck := fs.Bool("skip-key-permission-check", false,
		"do not refuse a CA key file readable by group/other; use only when the OS already isolates the file (e.g. a systemd LoadCredential file under /run/credentials)")
	fs.Parse(args)
	if *configPath == "" {
		return errors.New("serve: --config is required")
	}

	// Fail fast: an unreadable or invalid policy or CA key prevents
	// startup entirely.
	pol, err := policy.Load(*configPath)
	if err != nil {
		return err
	}
	signer, err := issuer.LoadCAKey(*caKeyFile, *skipKeyPermCheck)
	if err != nil {
		return err
	}

	log := audit.New()
	if *skipKeyPermCheck {
		log.Warn("CA key file permission check disabled (--skip-key-permission-check)")
	}
	srv := server.New(pol, signer, oidc.NewRemoteVerifier(), log)

	// Only the public key fingerprint is logged, never key material.
	log.Info("starting",
		"version", version,
		"listen", *listen,
		"ca_fingerprint", issuer.Fingerprint(signer),
		"policy", *configPath,
		"rules", len(pol.Rules),
		"disabled", pol.Disabled,
	)

	// SIGHUP reloads the policy. A reload that fails to parse or
	// validate keeps the current policy running and logs an error:
	// issuance must neither stop nor loosen because of a bad reload.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			newPol, err := policy.Load(*configPath)
			if err != nil {
				log.Error("policy reload failed; keeping current policy", "error", err.Error())
				continue
			}
			srv.SetPolicy(newPol)
			log.Info("policy reloaded", "rules", len(newPol.Rules), "disabled", newPol.Disabled)
		}
	}()

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(ctx)
	}
}
