package main

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Global flags
var (
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "hide",
	Short: "Hide messages in images",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		if verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		} else {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
