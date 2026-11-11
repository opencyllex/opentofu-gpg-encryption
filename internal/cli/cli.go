package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"opentofu-gpg-key-provider/internal/gpg"
	"opentofu-gpg-key-provider/internal/provider"
)

// Run serves one OpenTofu external key provider request and returns an exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	flags := flag.NewFlagSet("opentofu-gpg-key-provider", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var recipients recipientFlags
	flags.Var(&recipients, "recipient", "GPG recipient fingerprint (repeatable; defaults to GPG configuration)")
	executable := flags.String("gpg", "gpg", "GnuPG executable name or path")
	homeDir := flags.String("homedir", "", "GnuPG home directory (defaults to GPG's normal home resolution)")
	timeout := flags.Duration("timeout", 45*time.Second, "Time budget for metadata input and GPG operations")
	showVersion := flags.Bool("version", false, "Print the executable version and exit")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: opentofu-gpg-key-provider [options]")
		fmt.Fprintln(stderr, "\nProvides GPG-protected AES-256 keys to OpenTofu over stdin/stdout.")
		fmt.Fprintln(stderr, "With no --recipient, GPG uses default-recipient or default-recipient-self.")
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
	client := gpg.Client{Executable: *executable, HomeDir: *homeDir, Recipients: recipients}
	if err := provider.Run(ctx, stdin, stdout, client); err != nil {
		fmt.Fprintf(stderr, "opentofu-gpg-key-provider: %v\n", err)
		return 1
	}
	return 0
}

type recipientFlags []string

func (r *recipientFlags) String() string { return strings.Join(*r, ", ") }

func (r *recipientFlags) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("recipient must not be empty")
	}
	*r = append(*r, value)
	return nil
}
