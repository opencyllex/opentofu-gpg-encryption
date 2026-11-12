package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/opencyllex/opentofu-gpg-key-provider/internal/method"
	"github.com/opencyllex/opentofu-gpg-key-provider/internal/policy"
	"github.com/opencyllex/opentofu-gpg-key-provider/internal/provider"
)

// Run serves one external encryption-method or policy-provider request.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	var operation string
	if len(args) != 0 {
		switch args[0] {
		case "encrypt", "decrypt", "policy":
			operation, args = args[0], args[1:]
		}
	}
	flags := flag.NewFlagSet("opentofu-gpg-encryption", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var authorizedKeys authorizedKeyFlags
	flags.Var(&authorizedKeys, "authorized-key", "Full GPG primary-key fingerprint authorized to read and write (repeatable; defaults to the sole local key)")
	executable := flags.String("gpg", "gpg", "GnuPG executable name or path")
	homeDir := flags.String("homedir", "", "GnuPG home directory (defaults to GPG's normal home resolution)")
	timeout := flags.Duration("timeout", 45*time.Second, "Time budget for request input and GPG operations")
	showVersion := flags.Bool("version", false, "Print the executable version and exit")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: opentofu-gpg-encryption <encrypt|decrypt|policy> [options]")
		fmt.Fprintln(stderr, "\nEncrypt signs and encrypts OpenTofu payloads; decrypt verifies every signer.")
		fmt.Fprintln(stderr, "Policy transports public GPG settings through an optional external key provider.")
		fmt.Fprintln(stderr, "A sole eligible signing key is selected automatically; otherwise GPG selects signers.")
		fmt.Fprintln(stderr, "Without --authorized-key, decryption requires one unambiguous local key.")
		fmt.Fprintln(stderr, "Every configured local-user must be authorized when an explicit list is supplied.")
		fmt.Fprintln(stderr)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Unexpected positional arguments; use --help for usage.")
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "opentofu-gpg-encryption %s\n", version)
		return 0
	}
	if operation == "" {
		fmt.Fprintln(stderr, "Choose encrypt, decrypt, or policy; use --help for usage.")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "--timeout must be greater than zero.")
		return 2
	}
	if strings.TrimSpace(*executable) == "" {
		fmt.Fprintln(stderr, "--gpg must name a GnuPG executable.")
		return 2
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	config := policy.Config{Version: policy.Version, GPG: *executable, HomeDir: *homeDir, AuthorizedKeys: authorizedKeys}
	var err error
	if operation == "policy" {
		err = provider.Run(ctx, stdin, stdout, config)
	} else {
		err = method.Run(ctx, stdin, stdout, operation, config)
	}
	if err != nil {
		fmt.Fprintf(stderr, "opentofu-gpg-encryption: %v\n", err)
		return 1
	}
	return 0
}

type authorizedKeyFlags []string

func (a *authorizedKeyFlags) String() string { return strings.Join(*a, ", ") }

func (a *authorizedKeyFlags) Set(value string) error {
	fingerprint, err := policy.Fingerprint(value)
	if err != nil {
		return err
	}
	*a = append(*a, fingerprint)
	return nil
}
