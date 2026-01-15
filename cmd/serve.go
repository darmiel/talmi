package cmd

import (
	"context"
	"crypto/rand"
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
	"github.com/darmiel/talmi/internal/audit"
	"github.com/darmiel/talmi/internal/core"
	"github.com/darmiel/talmi/internal/engine"
	"github.com/darmiel/talmi/internal/issuers"
	"github.com/darmiel/talmi/internal/logging"
	"github.com/darmiel/talmi/internal/providers"
	"github.com/darmiel/talmi/internal/source"
	"github.com/darmiel/talmi/internal/store"
	"github.com/darmiel/talmi/internal/tasks"
	"github.com/darmiel/talmi/internal/validation"
)

var (
	serveAddr string
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Talmi server",
	Long: `Starts a HTTP server that processes OIDC tokens and issues downstream credentials.
This command requires a valid configuration file defining issuers, providers, and rules.`,
	Example: `  talmi serve --config /etc/talmi/config.yaml --addr :9090`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// initialize: load issuers, providers, rules engine
		cfg, err := f.LoadPolicyConfig()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		log.Info().Msg("Generating signing key for Talmi JWTs...")
		signingKey := make([]byte, 32)
		if _, err := rand.Read(signingKey); err != nil {
			return fmt.Errorf("generating signing key: %w", err)
		}

		log.Info().Msg("Initializing issuers...")
		issRegistry, err := issuers.BuildRegistry(cmd.Context(), cfg.Issuers)
		if err != nil {
			return fmt.Errorf("building issuer registry: %w", err)
		}

		log.Info().Msg("Initializing providers...")
		provRegistry, err := providers.BuildRegistry(cfg.Providers, signingKey)
		if err != nil {
			return fmt.Errorf("building provider registry: %w", err)
		}

		var auditor core.Auditor
		if cfg.Audit.Enabled {
			switch cfg.Audit.Type {
			case "jsonl":
				log.Info().Str("path", cfg.Audit.Path).Msg("Initializing auditor...")
				auditor, err = audit.NewFileAuditor(cfg.Audit.Path)
				if err != nil {
					return fmt.Errorf("initializing auditor: %w", err)
				}
				defer func() {
					if err := auditor.Close(); err != nil {
						log.Error().Err(err).Msg("closing auditor")
					}
				}()

			case "memory":
				log.Info().Msg("Using in-memory audit log")
				auditor = audit.NewInMemoryAuditor()

			default:
				return fmt.Errorf("unknown audit type: %s", cfg.Audit.Type)
			}

		} else {
			log.Warn().Msg("Audit logging is disabled")
			auditor = audit.NewNoopAuditor()
		}

		var tokenStore core.TokenStore
		// TODO: initialize token store based on config
		tokenStore = store.NewInMemoryTokenStore()

		policyMgr := engine.NewManager(cfg.Rules)
		taskMgr := tasks.NewManager()

		if cfg.PolicySource != nil {
			switch {
			case cfg.PolicySource.GitHub != nil:
				log.Info().Msg("Starting policy source sync from GitHub this will overwrite local rules...")

				fetcher, err := source.NewGitHubFetcher(*cfg.PolicySource.GitHub)
				if err != nil {
					return fmt.Errorf("initializing GitHub policy fetcher: %w", err)
				}

				knownIssuers := issRegistry.KnownIssuers()
				knownProviders := make(map[string]struct{})
				for name := range provRegistry {
					knownProviders[name] = struct{}{}
				}

				syncFunc := syncFetcher(fetcher, knownIssuers, knownProviders, policyMgr)
				log.Debug().Msg("Bootstrapping initial policy sync from GitHub...")

				bootCtx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
				defer cancel()

				if err := syncFunc(bootCtx, logging.NewZLogger(log.Logger)); err != nil {
					return fmt.Errorf("initial policy sync from GitHub: %w", err)
				}

				taskMgr.Register("git-sync", cfg.PolicySource.Sync.Interval, syncFunc)
			default:
				return fmt.Errorf("unsupported policy source configuration")
			}
		}

		// setup server
		srv := api.NewServer(policyMgr, taskMgr, issRegistry, provRegistry, auditor, tokenStore)

		server := &http.Server{
			Addr:    serveAddr,
			Handler: srv.Routes(signingKey),
		}

		go func() {
			log.Info().Msgf("Starting server on %s...", serveAddr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal().Err(err).Msg("Server crashed")
			}
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
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

	f.bindPolicyFlag(serveCmd.Flags())
	serveCmd.Flags().StringVar(&serveAddr, "addr", ":8080", "Address to listen on")

	_ = serveCmd.MarkFlagRequired("config")
}

func syncFetcher(
	fetcher source.Fetcher,
	knownIssuers, knownProviders map[string]struct{},
	policyMgr *engine.PolicyManager,
) tasks.TaskFunc {
	return func(ctx context.Context, logger logging.InternalLogger) error {
		logger.Debug("Starting policy fetch from source...")
		rules, err := fetcher.Fetch(ctx, logger)
		if err != nil {
			return fmt.Errorf("fetching rules: %w", err)
		}

		logger.Debug("Validating fetched rules...")
		validRules, err := validation.ValidateRules(rules, knownIssuers, knownProviders)
		if err != nil {
			return fmt.Errorf("validating fetched rules: %w", err)
		}

		logger.Debug("Updating policy manager with %d rules...", len(validRules))
		if err := policyMgr.Update(validRules); err != nil {
			return fmt.Errorf("updating policy manager: %w", err)
		}

		logger.Debug("Policy fetch and update completed successfully")
		return nil
	}
}
