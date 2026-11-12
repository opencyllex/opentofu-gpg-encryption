package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/opencyllex/opentofu-gpg-key-provider/internal/gpg"
	"github.com/opencyllex/opentofu-gpg-key-provider/internal/provider"
)

// Run serves one OpenTofu external key provider request and returns an exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	flags := flag.NewFlagSet("opentofu-gpg-key-provider", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var authorizedKeys authorizedKeyFlags
	flags.Var(&authorizedKeys, "authorized-key", "Full GPG primary-key fingerprint authorized to read and write (repeatable; defaults to the selected signing keys)")
	executable := flags.String("gpg", "gpg", "GnuPG executable name or path")
	homeDir := flags.String("homedir", "", "GnuPG home directory (defaults to GPG's normal home resolution)")
	timeout := flags.Duration("timeout", 45*time.Second, "Time budget for metadata input and GPG operations")
	showVersion := flags.Bool("version", false, "Print the executable version and exit")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: opentofu-gpg-key-provider [options]")
		fmt.Fprintln(stderr, "\nProvides GPG-signed and encrypted AES-256 keys to OpenTofu over stdin/stdout.")
		fmt.Fprintln(stderr, "With no --authorized-key, authorize the selected signing keys.")
		fmt.Fprintln(stderr, "A sole eligible signing key is selected automatically; otherwise GPG uses local-user, default-key, or its first secret key.")
		fmt.Fprintln(stderr, "Every configured local-user must be authorized.")
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
		fmt.Fprintf(stdout, "opentofu-gpg-key-provider %s\n", version)
		return 0
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
	client := &gpg.Client{Executable: *executable, HomeDir: *homeDir, AuthorizedKeys: authorizedKeys}
	if err := provider.Run(ctx, stdin, stdout, client); err != nil {
		fmt.Fprintf(stderr, "opentofu-gpg-key-provider: %v\n", err)
		return 1
	}
	return 0
}

type authorizedKeyFlags []string

func (a *authorizedKeyFlags) String() string { return strings.Join(*a, ", ") }

func (a *authorizedKeyFlags) Set(value string) error {
	if len(value) != 40 && len(value) != 64 {
		return errors.New("authorized key must be a full GPG primary-key fingerprint (40 or 64 hexadecimal characters)")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return errors.New("authorized key fingerprint must contain only hexadecimal characters")
	}
	*a = append(*a, strings.ToUpper(value))
	return nil
}
