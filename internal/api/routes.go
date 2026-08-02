package api

const (
	HealthCheckRoute = "/healthz"
	AboutRoute       = "/icanhaztalmi"

	IssueTokenRoute  = "/v2/token/issue"
	RevokeTokenRoute = "/v2/token/revoke"

	WebhookGitHubRoute = "/v2/webhooks/github"

	LoginRoute       = "/v2/auth/session"
	LoginConfigRoute = "/v2/auth/config"

	AuditParent     = "/v2/audit"
	AuditQueryRoute = AuditParent

	TaskParent       = "/v2/tasks"
	ListTasksRoute   = TaskParent
	TriggerTaskRoute = TaskParent + "/{name}/trigger"
	TaskLogsRoute    = TaskParent + "/{name}/logs"

	//AuditParent           = "/v1/audit/"
	//ListAuditsRoute       = AuditParent + "audits"
	//ListActiveTokensRoute = AuditParent + "tokens"
	//ExplainRoute          = AuditParent + "explain"
	//
	//TaskParent       = "/v1/tasks/"
	//ListTasksRoute   = TaskParent
	//TriggerTaskRoute = TaskParent + "{name}/trigger"
	//LogsForTaskRoute = TaskParent + "{name}/logs"
)
