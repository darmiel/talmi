package client

import (
	"context"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/tasks"
)

func (c *Client) ListTasks(ctx context.Context) ([]tasks.TaskStatus, string, error) {
	var out []tasks.TaskStatus
	correlationID, err := c.get(ctx, c.url(api.ListTasksRoute).build(), &out)
	return out, correlationID, err
}

func (c *Client) TriggerTask(ctx context.Context, name string) (string, error) {
	return c.post(ctx, c.url(api.TriggerTaskRoute).
		setPathParam("name", name).
		build(), nil, nil)
}

func (c *Client) TaskLogs(ctx context.Context, name string) ([]tasks.LogEntry, string, error) {
	var out []tasks.LogEntry
	correlationID, err := c.get(ctx, c.url(api.TaskLogsRoute).
		setPathParam("name", name).
		build(), &out)
	return out, correlationID, err
}
