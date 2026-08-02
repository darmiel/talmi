package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cliconfig"
	"github.com/darmiel/talmi/pkg/client"
)

var loginWithToken string

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to a Talmi server via your GitHub account",
	Long: `Logs in to a Talmi server. By default this runs a GitHub device-authorization
flow (open a URL, enter a code). Use --with-token to exchange a GitHub access
token you already hold, skipping the browser step.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()

		server, err := f.GetRemoteAddr()
		if err != nil {
			return err
		}
		cli := client.New(server)

		info, correlationID, err := cli.GetLoginInfo(ctx)
		if err != nil {
			return logError(err, correlationID, "could not fetch the server's login config endpoint")
		}
		if info.ClientID == "" || info.Server == "" {
			return fmt.Errorf("this server does not have interactive login configured")
		}

		ghesToken := loginWithToken
		if ghesToken == "" {
			ghesToken, err = runDeviceFlow(ctx, info)
			if err != nil {
				return err
			}
			log.Info().Msg("device flow completed, exchanging token for Talmi session...")
		}

		session, correlationID, err := cli.ExchangeSession(ctx, ghesToken)
		if err != nil {
			return logError(err, correlationID, "session exchange failed")
		}

		cfg, err := cliconfig.LoadOrNew()
		if err != nil {
			return err
		}
		if err := cfg.SetCredential(server, session.Token); err != nil {
			return err
		}

		logSuccess("logged in to %s (session valid until %s)",
			server, session.ExpiresAt.Local().Format(time.RFC1123))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().StringVar(&loginWithToken, "with-token", "",
		"Exchange a GitHub access token directly, skipping the device flow")
}

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type deviceTokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func runDeviceFlow(ctx context.Context, info *client.LoginInfo) (string, error) {
	dc, err := requestDeviceCode(ctx, info)
	if err != nil {
		return "", fmt.Errorf("requesting device code: %w", err)
	}

	fmt.Println()
	fmt.Printf("  Your one-time code:\t%s\n", bold(dc.UserCode))
	fmt.Printf("  Open in a browser:\t%s\n", dc.VerificationURI)
	fmt.Println()
	fmt.Println(faint("  Waiting for you to authorize the device..."))

	return pollForToken(ctx, info, dc)
}

func requestDeviceCode(ctx context.Context, info *client.LoginInfo) (*deviceCodeResponse, error) {
	form := url.Values{
		"client_id": {info.ClientID},
		"scope":     {strings.Join(info.Scopes, " ")},
	}
	endpoint := strings.TrimRight(info.Server, "/") + "/login/device/code"
	var out deviceCodeResponse
	if err := postForm(ctx, endpoint, form, &out); err != nil {
		return nil, err
	}
	if out.DeviceCode == "" {
		return nil, fmt.Errorf("empty device code returned %s", endpoint)
	}
	return &out, nil
}

func pollForToken(ctx context.Context, info *client.LoginInfo, dc *deviceCodeResponse) (string, error) {
	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	endpoint := strings.TrimRight(info.Server, "/") + "/login/oauth/access_token"

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return "", fmt.Errorf("code expired, run `talmi login` again")
		}

		form := url.Values{
			"client_id":   {info.ClientID},
			"device_code": {dc.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}
		var tok deviceTokenResponse
		if err := postForm(ctx, endpoint, form, &tok); err != nil {
			return "", err
		}
		switch {
		case tok.AccessToken != "":
			return tok.AccessToken, nil
		case tok.Error == "authorization_pending":
		// keep polling
		case tok.Error == "slow_down":
			interval += 5 * time.Second
		case tok.Error == "access_denied":
			return "", fmt.Errorf("authorization denied")
		case tok.Error == "expired_token":
			return "", fmt.Errorf("code expired, run `talmi login` again")
		default:
			return "", fmt.Errorf("unexpected error from server: %s - %s", tok.Error, tok.ErrorDescription)
		}
	}
}

func postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", endpoint, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server %s returned status %d", endpoint, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
