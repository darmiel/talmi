package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"

	"github.com/darmiel/talmi/internal/cli"
	"github.com/darmiel/talmi/internal/cli/ui"
	"github.com/darmiel/talmi/internal/cliconfig"
	"github.com/darmiel/talmi/pkg/client"
)

func newSessionCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage authentication to a Talmi server",
	}
	cmd.AddCommand(
		newSessionLoginCmd(deps),
		newSessionLogoutCmd(deps),
		newSessionStatusCmd(deps),
	)
	return cmd
}

func newSessionLoginCmd(deps Deps) *cobra.Command {
	var withToken string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate via your GitHub account",
		Long: `Logs in to a Talmi server. By default this runs a GitHub device-authorization
flow (open a URL, enter a code). Use --with-token to exchange a GitHub access
token you already hold, skipping the browser step.`,
		Args: cobra.NoArgs,
	}
	cmd.Flags().StringVar(&withToken, "with-token", "",
		"Exchange a GitHub access token directly, skipping the device flow")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		server, err := deps.RemoteAddr()
		if err != nil {
			return err
		}
		c, err := deps.NewClient()
		if err != nil {
			return err
		}

		info, correlation, err := c.GetLoginInfo(ctx)
		if err != nil {
			return clientError(err, correlation)
		}
		if info.ClientID == "" || info.Server == "" {
			return &cli.ExitError{
				Code:    cli.CodeGeneric,
				Message: "this server does not have interactive login configured",
			}
		}

		ghToken := withToken
		if ghToken == "" {
			ghToken, err = runDeviceFlow(ctx, deps, info)
			if err != nil {
				return err
			}
		}

		session, correlation, err := c.ExchangeSession(ctx, ghToken)
		if err != nil {
			return clientError(err, correlation)
		}

		cfg, err := cliconfig.LoadOrNew()
		if err != nil {
			return err
		}
		if err := cfg.SetCredential(server, session.Token); err != nil {
			return err
		}
		if err := cliconfig.Save(cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		ui.New(deps.IO.ErrOut, deps.IO.Color).Successln("logged in to %s (session valid until %s)",
			server, session.ExpiresAt.Local().Format(time.RFC1123))
		return nil
	}
	return cmd
}

func newSessionLogoutCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Clear the saved credential for the current server",
		Args:  cobra.NoArgs,
	}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		server, err := deps.RemoteAddr()
		if err != nil {
			return err
		}
		cfg, err := cliconfig.LoadOrNew()
		if err != nil {
			return err
		}
		removed, err := cfg.DeleteCredential(server)
		if err != nil {
			return err
		}
		if err := cliconfig.Save(cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}
		p := ui.New(deps.IO.ErrOut, deps.IO.Color)
		if removed {
			p.Successln("logged out of %s", server)
		} else {
			p.Warnln("no saved credential for %s", server)
		}
		return nil
	}
	return cmd
}

func newSessionStatusCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the current authentication status for the Talmi server",
		Args:  cobra.NoArgs,
	}
	jsonOut := addJSONFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		server, err := deps.RemoteAddr()
		if err != nil {
			return err
		}
		cfg, err := cliconfig.LoadOrNew()
		if err != nil {
			return err
		}
		cred, _ := cfg.GetCredential(server)

		status := struct {
			Server        string `json:"server"`
			Authenticated bool   `json:"authenticated"`
			Expires       string `json:"expires"`
		}{
			Server:        server,
			Authenticated: cred != nil,
		}
		if cred != nil {
			if exp := jwtExpiry(cred.Token); !exp.IsZero() {
				status.Expires = exp.Local().Format(time.RFC3339)
			}
		}

		notLoggedIn := &cli.ExitError{
			Code:    cli.CodeAuth,
			Message: fmt.Sprintf("not logged in to %s", server),
			Hint:    "run 'talmi session login'",
		}
		if *jsonOut {
			if err := emitJSON(deps, status); err != nil {
				return err
			}
			if !status.Authenticated {
				return notLoggedIn
			}
			return nil
		}
		if !status.Authenticated {
			return notLoggedIn
		}
		pairs := [][2]string{{"Server", server}, {"Status", "authenticated"}}
		if status.Expires != "" {
			pairs = append(pairs, [2]string{"Expires", status.Expires})
		}
		ui.WriteKV(deps.IO.Out, deps.IO.Color, pairs)
		return nil
	}
	return cmd
}

func jwtExpiry(token string) time.Time {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return time.Time{}
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}
	}
	if exp, ok := claims["exp"].(float64); ok {
		return time.Unix(int64(exp), 0)
	}
	return time.Time{}
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

func runDeviceFlow(ctx context.Context, deps Deps, info *client.LoginInfo) (string, error) {
	dc, err := requestDeviceCode(ctx, info)
	if err != nil {
		return "", fmt.Errorf("requesting device code: %w", err)
	}

	p := ui.New(deps.IO.ErrOut, deps.IO.Color)
	p.Println()
	p.Printf("  one-time code:  ")
	p.Boldln("%s", dc.UserCode)
	p.Printf("  open:           %s\n\n", dc.VerificationURI)

	sp := ui.NewSpinner(deps.IO.ErrOut, deps.IO.IsTTY)
	sp.Start("waiting for authorization...")

	token, err := pollForToken(ctx, info, dc)
	if err != nil {
		sp.Stop("authorization failed")
		return "", &cli.ExitError{
			Code:    cli.CodeAuth,
			Message: err.Error(),
			Cause:   err,
		}
	}
	sp.Stop("authorization completed." + strings.Repeat(" ", 10)) // TODO: remove the extra spaces when spinner stops, this is a hack to avoid the spinner overwriting the last line
	return token, nil
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

	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return "", fmt.Errorf("code expired, run `talmi session login` again")
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
			return "", fmt.Errorf("code expired, run `talmi session login` again")
		default:
			return "", fmt.Errorf("unexpected error from server: %s - %s", tok.Error, tok.ErrorDescription)
		}
		timer.Reset(interval)
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
