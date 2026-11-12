package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/opencyllex/opentofu-gpg-key-provider/internal/cli"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version)
	stop()
	os.Exit(code)
}
