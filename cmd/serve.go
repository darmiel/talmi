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
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Talmi server",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		cfg, err := config.Load(serveConfigPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		src, err := buildSource(cfg, filepath.Dir(serveConfigPath))
		if err != nil {
			return fmt.Errorf("building config source: %w", err)
		}

		log.Info().
			Bool("dev", serveDevMode).
			Msg("building runtime manager...")

		mgr, err := runtime.NewManager(ctx, cfg, src, serveDevMode)
		if err != nil {
			return fmt.Errorf("building runtime manager: %w", err)
		}
		defer func() {
			if err := mgr.Close(); err != nil {
				log.Error().Err(err).Msg("closing runtime manager")
			}
		}()

		taskMgr := tasks.NewManager()
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

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server forced to shutdown: %w", err)
		}
		log.Info().Msg("server stopped")
		return nil
		//
		//// initialize: load issuers, providers, rules engine
		//cfg, err := f.LoadPolicyConfig()
		//if err != nil {
		//	return fmt.Errorf("loading config: %w", err)
		//}
		//
		//log.Info().Msg("Generating signing key for Talmi JWTs...")
		//signingKey := make([]byte, 32)
		//if _, err := rand.Read(signingKey); err != nil {
		//	return fmt.Errorf("generating signing key: %w", err)
		//}
		//
		//log.Info().Msg("Initializing issuers...")
		//issRegistry, err := issuers.BuildRegistry(cmd.Context(), cfg.Issuers)
		//if err != nil {
		//	return fmt.Errorf("building issuer registry: %w", err)
		//}
		//
		//log.Info().Msg("Initializing providers...")
		//provRegistry, err := providers.BuildRegistry(cfg.Providers, signingKey)
		//if err != nil {
		//	return fmt.Errorf("building provider registry: %w", err)
		//}
		//
		//var auditor core.Auditor
		//if cfg.Audit.Enabled {
		//	switch cfg.Audit.Type {
		//	case "jsonl":
		//		log.Info().Str("path", cfg.Audit.Path).Msg("Initializing auditor...")
		//		auditor, err = audit.NewFileAuditor(cfg.Audit.Path)
		//		if err != nil {
		//			return fmt.Errorf("initializing auditor: %w", err)
		//		}
		//		defer func() {
		//			if err := auditor.Close(); err != nil {
		//				log.Error().Err(err).Msg("closing auditor")
		//			}
		//		}()
		//
		//	case "memory":
		//		log.Info().Msg("Using in-memory audit log")
		//		auditor = audit.NewInMemoryAuditor()
		//
		//	default:
		//		return fmt.Errorf("unknown audit type: %s", cfg.Audit.Type)
		//	}
		//
		//} else {
		//	log.Warn().Msg("Audit logging is disabled")
		//	auditor = audit.NewNoopAuditor()
		//}
		//
		//var tokenStore core.TokenStore
		//// TODO: initialize token store based on config
		//tokenStore = store.NewInMemoryTokenStore()
		//
		//policyMgr := engine.NewManager(cfg.Rules)
		//taskMgr := tasks.NewManager()
		//
		//taskMgr.Register("token-cleanup", 1*time.Hour, func(ctx context.Context, logger logging.InternalLogger) error {
		//	count, err := tokenStore.DeleteExpired(ctx)
		//	if err != nil {
		//		return err
		//	}
		//	if count > 0 {
		//		logger.Info("Deleted %d expired tokens", count)
		//	} else {
		//		logger.Info("No expired tokens to delete")
		//	}
		//	return nil
		//})
		//
		//if cfg.PolicySource != nil {
		//	switch {
		//	case cfg.PolicySource.GitHub != nil:
		//		log.Info().Msg("Starting policy source sync from GitHub this will overwrite local rules...")
		//
		//		fetcher, err := source.NewGitHubFetcher(*cfg.PolicySource.GitHub)
		//		if err != nil {
		//			return fmt.Errorf("initializing GitHub policy fetcher: %w", err)
		//		}
		//
		//		knownIssuers := issRegistry.KnownIssuers()
		//		knownProviders := make(map[string]struct{})
		//		for name := range provRegistry {
		//			knownProviders[name] = struct{}{}
		//		}
		//
		//		syncFunc := syncFetcher(fetcher, knownIssuers, knownProviders, policyMgr)
		//		log.Debug().Msg("Bootstrapping initial policy sync from GitHub...")
		//
		//		bootCtx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		//		defer cancel()
		//
		//		if err := syncFunc(bootCtx, logging.NewZLogger(log.Logger)); err != nil {
		//			return fmt.Errorf("initial policy sync from GitHub: %w", err)
		//		}
		//
		//		taskMgr.Register("git-sync", cfg.PolicySource.Sync.Interval, syncFunc)
		//	default:
		//		return fmt.Errorf("unsupported policy source configuration")
		//	}
		//}
		//
		//// setup server
		//srv := api.NewServer(
		//	policyMgr,
		//	taskMgr,
		//	issRegistry,
		//	provRegistry,
		//	auditor,
		//	tokenStore,
		//	cfg,
		//)
		//
		//server := &http.Server{
		//	Addr:    serveAddr,
		//	Handler: srv.Routes(signingKey),
		//}
		//
		//go func() {
		//	log.Info().Msgf("Starting server on %s...", serveAddr)
		//	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		//		log.Fatal().Err(err).Msg("Server crashed")
		//	}
		//}()
		//
		//quit := make(chan os.Signal, 1)
		//signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		//<-quit
		//log.Info().Msg("Shutting down server...")
		//
		//ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		//defer cancel()
		//
		//if err := server.Shutdown(ctx); err != nil {
		//	return fmt.Errorf("server forced to shutdown: %w", err)
		//}
		//
		//log.Info().Msg("Server exited")
		//return nil
	},
}

func buildSource(cfg *config.Config, baseDir string) (source.Source, error) {
	if cfg.ConfigSource != nil && cfg.ConfigSource.GitHub != nil {
		key, err := secret.Resolve(cfg.ConfigSource.GitHub.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("resolving config source key: %w", err)
		}
		return source.NewGitHubSource(*cfg.ConfigSource.GitHub, key)
	}
	return source.NewLocalSource(baseDir, cfg), nil
}

func init() {
	rootCmd.AddCommand(serveCmd)

	//f.bindPolicyFlag(serveCmd.Flags())
	serveCmd.Flags().StringVarP(&serveConfigPath, "config", "c", "talmi.yaml", "Bootstrap config file")
	serveCmd.Flags().StringVar(&serveAddr, "addr", ":8080", "Address to listen on")
	serveCmd.Flags().BoolVar(&serveDevMode, "dev", false, "Dev mode: real providers replaced with in-memory stubs")
}

//
//func syncFetcher(
//	fetcher source.Fetcher,
//	knownIssuers, knownProviders map[string]struct{},
//	policyMgr *engine.PolicyManager,
//) tasks.TaskFunc {
//	return func(ctx context.Context, logger logging.InternalLogger) error {
//		logger.Debug("Starting policy fetch from source...")
//		rules, err := fetcher.Fetch(ctx, logger)
//		if err != nil {
//			return fmt.Errorf("fetching rules: %w", err)
//		}
//
//		logger.Debug("Validating fetched rules...")
//		validRules, err := validation.ValidateRules(rules, knownIssuers, knownProviders)
//		if err != nil {
//			return fmt.Errorf("validating fetched rules: %w", err)
//		}
//
//		logger.Debug("Updating policy manager with %d rules...", len(validRules))
//		if err := policyMgr.Update(validRules); err != nil {
//			return fmt.Errorf("updating policy manager: %w", err)
//		}
//
//		logger.Debug("Policy fetch and update completed successfully")
//		return nil
//	}
//}
