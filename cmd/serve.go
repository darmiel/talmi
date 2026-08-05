package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/logging"
	"github.com/darmiel/talmi/internal/runtime"
	"github.com/darmiel/talmi/internal/secret"
	"github.com/darmiel/talmi/internal/source"
	"github.com/darmiel/talmi/internal/tasks"
)

var (
	serveConfigPath string
	serveAddr       string
	serveDevMode    bool
	serveLocal      bool
	serveRef        string
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Talmi server",
	RunE: func(cmd *cobra.Command, args []string) error {
		appCtx, cancelApp := context.WithCancel(cmd.Context())
		defer cancelApp()

		cfg, err := config.Load(serveConfigPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		if err := validateVetSourceFlags(serveLocal, serveRef); err != nil {
			return fmt.Errorf("invalid source flags: %w", err)
		}

		src, err := source.Resolve(cfg, filepath.Dir(serveConfigPath), source.Options{
			ForceLocal: serveLocal,
			Ref:        serveRef,
		})
		if err != nil {
			return fmt.Errorf("resolving config source: %w", err)
		}

		log.Info().
			Bool("dev", serveDevMode).
			Msg("building runtime manager...")

		mgr, err := runtime.NewManager(appCtx, cfg, src, serveDevMode)
		if err != nil {
			return fmt.Errorf("building runtime manager: %w", err)
		}
		defer func() {
			if err := mgr.Close(); err != nil {
				log.Error().Err(err).Msg("closing runtime manager")
			}
		}()

		taskMgr := tasks.NewManager(appCtx)
		if cfg.ConfigSource != nil && cfg.ConfigSource.Sync.Interval > 0 {
			taskMgr.Register("config-sync", cfg.ConfigSource.Sync.Interval,
				func(ctx context.Context, logger logging.InternalLogger) error {
					return mgr.Reload(ctx)
				})
		}
		taskMgr.Register("lease-cleanup", 15*time.Minute,
			func(ctx context.Context, logger logging.InternalLogger) error {
				n, err := mgr.Current().LeaseStore.DeleteExpired(ctx)
				if err == nil && n > 0 {
					logger.Info("deleted %d expired leases", n)
				}
				return err
			})

		var opts []api.Option
		if cfg.ConfigSource != nil && cfg.ConfigSource.GitHub != nil && cfg.ConfigSource.GitHub.WebhookSecret != "" {
			log.Info().Msg("enabling GitHub webhook endpoint for config source")

			sec, err := secret.Resolve(cfg.ConfigSource.GitHub.WebhookSecret)
			if err != nil {
				return fmt.Errorf("resolving GitHub webhook secret: %w", err)
			}
			opts = append(opts, api.WithGitHubWebhook(sec, func(ctx context.Context) error {
				if err := mgr.Reload(ctx); err != nil {
					return err
				}
				mgr.InvalidateProviders()
				return nil
			}))
		}

		// admin functionality
		if cfg.Auth != nil {
			log.Info().Msg("enabling admin endpoints")

			ttl := cfg.Auth.SessionTTL
			if ttl == 0 {
				ttl = 8 * time.Hour
			}
			opts = append(opts, api.WithAdmin(api.AdminConfig{
				LoginIssuer: func() (core.Issuer, bool) {
					return mgr.Current().Issuers.Get(cfg.Auth.LoginIssuer)
				},
				SessionIssuer: func() (core.Issuer, bool) {
					return mgr.Current().Issuers.Get(cfg.Auth.SessionIssuer)
				},
				Authorize: func(principal *core.Principal, req []core.ResourceRequest) core.Decision {
					return mgr.Current().Engine.GetEngine().Authorize(principal, req)
				},
				Auditor: func() core.Auditor {
					return mgr.Current().Auditor
				},
				Tasks:         taskMgr,
				SessionSigner: mgr.SessionSigner(),
				SessionTTL:    ttl,
				LoginInfo: api.LoginInfo{
					Server:   cfg.Auth.Server,
					ClientID: cfg.Auth.ClientID,
					Scopes:   cfg.Auth.Scopes,
				},
			}))
		}

		srv := api.NewServer(func() api.TokenService {
			return mgr.Current().Service
		}, opts...)
		server := &http.Server{
			Addr:              serveAddr,
			Handler:           srv.Routes(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}

		serverErr := make(chan error, 1)
		go func() {
			log.Info().
				Str("addr", serveAddr).
				Msg("talmi listening")
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErr <- err
			}
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

		select {
		case err := <-serverErr:
			return fmt.Errorf("server error: %w", err)
		case sig := <-quit:
			log.Info().
				Str("signal", sig.String()).
				Msg("shutting down...")
		}

		cancelApp() // stop task schedulers + cancel task runs

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server forced to shutdown: %w", err)
		}
		log.Info().Msg("server stopped. waiting for tasks to finish...")
		taskMgr.Wait()

		log.Info().Msg("bye!")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// f.bindPolicyFlag(serveCmd.Flags())
	serveCmd.Flags().StringVarP(&serveConfigPath, "config", "c", "talmi.yaml", "Bootstrap config file")
	serveCmd.Flags().StringVar(&serveAddr, "addr", ":8080", "Address to listen on")
	serveCmd.Flags().BoolVar(&serveDevMode, "dev", false, "Dev mode: real providers replaced with in-memory stubs")
	serveCmd.Flags().BoolVar(&serveLocal, "local", false, "Force local config source (ignores remote)")
	serveCmd.Flags().StringVar(&serveRef, "ref", "", "Override git ref for remote config source")
}
