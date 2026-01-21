package api

const (
	HealthCheckRoute = "/healthz"
	AboutRoute       = "/icanhaztalmi"

	IssueTokenRoute  = "/v1/token/issue"
	RevokeTokenRoute = "/v1/token/revoke"

	WebhookRoute = "/v1/webhooks/github"

	AuditParent           = "/v1/audit/"
	ListAuditsRoute       = AuditParent + "audits"
	ListActiveTokensRoute = AuditParent + "tokens"
	ExplainRoute          = AuditParent + "explain"

	TaskParent       = "/v1/tasks/"
	ListTasksRoute   = TaskParent
	TriggerTaskRoute = TaskParent + "{name}/trigger"
	LogsForTaskRoute = TaskParent + "{name}/logs"
)
