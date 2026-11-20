package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/dmarcguardhq/parse-dmarc/cmd/server"
	"github.com/dmarcguardhq/parse-dmarc/internal/logger"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	cli.VersionPrinter = func(c *cli.Command) {
		fmt.Println(version)
	}

	cmd := server.Command(version, commit, date, builtBy)

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		// LOG_FORMAT applies to the last line too: a log pipeline that reads
		// JSON should see why the process exited.
		log, _ := logger.New("error", os.Getenv("LOG_FORMAT"), false)
		log.Fatal().Err(err).Msg("failed to run")
	}
}
