package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
	"github.com/darmiel/talmi/internal/providers"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the Talmi server",
	// Long: "", // TODO
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")

		// initialize: load issuers, providers, rules engine
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		log.Info().Msg("Initializing issuers...")
		issRegistry, err := issuers.BuildRegistry(cmd.Context(), cfg.Issuers)
		if err != nil {
			return fmt.Errorf("building issuer registry: %w", err)
		}

		log.Info().Msg("Initializing providers...")
		provRegistry, err := providers.BuildRegistry(cfg.Providers)
		if err != nil {
			return fmt.Errorf("building provider registry: %w", err)
		}

		eng := engine.New(cfg.Rules)

		// setup server
		srv := api.NewServer(eng, issRegistry, provRegistry)

		server := &http.Server{
			Addr:    addr,
			Handler: srv.Routes(),
		}

		go func() {
			log.Info().Msgf("Starting server on %s...", addr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal().Err(err).Msg("Server crashed")
			}
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINFO, syscall.SIGTERM)
		<-quit
		log.Info().Msg("Shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("server forced to shutdown: %w", err)
		}

		log.Info().Msg("Server exited")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().String("addr", ":8080", "address to listen on")
}
