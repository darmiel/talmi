package api

const (
	HealthCheckRoute = "/healthz"
	AboutRoute       = "/icanhaztalmi"

	TokenParent      = "/v2/token"
	IssueTokenRoute  = TokenParent + "/issue"
	RevokeTokenRoute = TokenParent + "/revoke"
	ExplainRoute     = TokenParent + "/explain"

	WebhookGitHubRoute = "/v2/webhooks/github"

	LoginRoute       = "/v2/auth/session"
	LoginConfigRoute = "/v2/auth/config"

	ProvidersRoute = "/v2/providers"
	ResolveRoute   = "/v2/resolve"

	AuditParent     = "/v2/audit"
	AuditQueryRoute = AuditParent
	AuditEntryRoute = AuditParent + "/{id}"

	TaskParent       = "/v2/tasks"
	ListTasksRoute   = TaskParent
	TriggerTaskRoute = TaskParent + "/{name}/trigger"
	TaskLogsRoute    = TaskParent + "/{name}/logs"
)
