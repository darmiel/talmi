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
	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/config"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/logging"
	"github.com/darmiel/talmi/internal/runtime"
	"github.com/darmiel/talmi/internal/secret"
	"github.com/darmiel/talmi/internal/source"
	"github.com/darmiel/talmi/internal/tasks"
)

func newServerCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run and manage the Talmi server",
	}
	cmd.AddCommand(newServerRunCmd(deps))
	return cmd
}

func newServerRunCmd(_ Deps) *cobra.Command {
	var (
		configPath string
		addr       string
		devMode    bool
		local      bool
		ref        string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the Talmi server",
		Args:  cobra.NoArgs,
	}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		appCtx, cancelApp := context.WithCancel(cmd.Context())
		defer cancelApp()

		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		if err := validateVetSourceFlags(local, ref); err != nil {
			return fmt.Errorf("invalid source flags: %w", err)
		}

		src, err := source.Resolve(cfg, filepath.Dir(configPath), source.Options{
			ForceLocal: local,
			Ref:        ref,
		})
		if err != nil {
			return fmt.Errorf("resolving config source: %w", err)
		}

		log.Info().
			Bool("dev", devMode).
			Msg("building runtime manager...")

		mgr, err := runtime.NewManager(appCtx, cfg, src, devMode)
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
					reloadErr := mgr.Reload(ctx)
					recordReload(ctx, mgr, reloadErr)
					return reloadErr
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

		opts, err := buildServerOptions(cfg, mgr, taskMgr)
		if err != nil {
			return err
		}

		srv := api.NewServer(func() api.TokenService {
			return mgr.Current().Service
		}, opts...)
		server := &http.Server{
			Addr:              addr,
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
				Str("addr", addr).
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
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "talmi.yaml", "Bootstrap config file")
	cmd.Flags().StringVar(&addr, "addr", ":8080", "Address to listen on")
	cmd.Flags().BoolVar(&devMode, "dev", false, "Dev mode: real providers replaced with in-memory stubs")
	cmd.Flags().BoolVar(&local, "local", false, "Force local config source (ignores remote)")
	cmd.Flags().StringVar(&ref, "ref", "", "Override git ref for remote config source")
	return cmd
}

func buildServerOptions(cfg *config.Config, mgr *runtime.Manager, taskMgr *tasks.Manager) ([]api.Option, error) {
	opts := []api.Option{
		api.WithRecorder(func() *audit.Recorder {
			return mgr.Current().Recorder
		}),
	}

	if cfg.ConfigSource != nil && cfg.ConfigSource.GitHub != nil && cfg.ConfigSource.GitHub.WebhookSecret != "" {
		log.Info().Msg("enabling GitHub webhook endpoint for config source")

		sec, err := secret.Resolve(cfg.ConfigSource.GitHub.WebhookSecret)
		if err != nil {
			return nil, fmt.Errorf("resolving GitHub webhook secret: %w", err)
		}
		opts = append(opts, api.WithGitHubWebhook(sec, func(ctx context.Context) error {
			reloadErr := mgr.Reload(ctx)
			recordReload(ctx, mgr, reloadErr)
			if reloadErr != nil {
				return reloadErr
			}
			mgr.InvalidateProviders()
			return nil
		}))
	}

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

	return opts, nil
}

func recordReload(ctx context.Context, mgr *runtime.Manager, err error) {
	rec := mgr.Current().Recorder
	if rec == nil {
		return
	}
	outcome := core.OutcomeSuccess
	if err != nil {
		outcome = core.OutcomeFailure
	}
	if recordErr := rec.Record(ctx, core.ActionConfigReload, outcome,
		audit.WithRevision(mgr.Current().Revision),
		audit.WithError(err),
	); recordErr != nil {
		log.Ctx(ctx).Error().Err(recordErr).Msg("recording config.reload failed")
	}
}
