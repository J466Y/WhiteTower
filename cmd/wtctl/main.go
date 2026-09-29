// Command wtctl is the command-line client of White Tower.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/J466Y/WhiteTower/internal/cli"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cli.NewRootCommand().ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}
