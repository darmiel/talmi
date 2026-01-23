package github

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v80/github"
)

func NewRawClient(signedToken, enterpriseURL string) (*github.Client, error) {
	// we can now use this signed JWT to authenticate as the GitHub App
	client := github.NewClient(nil).WithAuthToken(signedToken)

	if enterpriseURL != "" {
		// we don't interact with uploads, so just use a dummy URL here.
		var err error
		client, err = client.WithEnterpriseURLs(enterpriseURL, enterpriseURL)
		if err != nil {
			return nil, fmt.Errorf("creating github enterprise client: %w", err)
		}
	}

	return client, nil
}

// NewClient creates an authenticated GitHub client using an App ID and private key.
// If enterpriseURL is non-empty, it configures the client for GitHub Enterprise.
// Note that you cannot use media uploads with this client as it uses the same URL for both base and upload.
func NewClient(appID int64, privateKey []byte, enterpriseURL string) (*github.Client, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing github app private key: %w", err)
	}

	// create and sign a JWT for the GitHub App using the private key
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("signing github app jwt: %w", err)
	}

	return NewRawClient(signedToken, enterpriseURL)
}

// InstallationTokenClient creates a GitHub client authenticated as the installation
// with the given installation ID, using the provided appClient to create the installation token.
func InstallationTokenClient(ctx context.Context, appClient *github.Client, instID int64) (*github.Client, error) {
	token, _, err := appClient.Apps.CreateInstallationToken(ctx, instID, nil)
	if err != nil {
		return nil, fmt.Errorf("creating installation token for installation ID %d: %w", instID, err)
	}
	client := github.NewClient(nil).WithAuthToken(token.GetToken())

	if appClient.BaseURL.String() != "https://api.github.com/" {
		client, err = client.WithEnterpriseURLs(appClient.BaseURL.String(), appClient.UploadURL.String())
		if err != nil {
			return nil, fmt.Errorf("creating github enterprise client: %w", err)
		}
	}

	return client, nil
}
