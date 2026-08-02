package api

const (
	HealthCheckRoute = "/healthz"
	AboutRoute       = "/icanhaztalmi"

	IssueTokenRoute  = "/v2/token/issue"
	RevokeTokenRoute = "/v2/token/revoke"

	WebhookGitHubRoute = "/v2/webhooks/github"

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
