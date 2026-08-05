package config

const (
	StoreMemory   = "memory"
	StorePostgres = "postgres"

	AuditPostgres = "postgres"
	AuditMemory   = "memory"
	AuditNoop     = "noop"

	SigningES256 = "ES256"
	SigningHS256 = "HS256"

	IssuerTypeOIDC         = "oidc"
	IssuerTypeStatic       = "static"
	IssuerTypeGitHubOAuth  = "github-oauth"
	IssuerTypeTalmiSession = "talmi-session"
)
