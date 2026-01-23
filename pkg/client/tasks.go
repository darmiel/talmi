package client

import (
	"context"
	"fmt"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/tasks"
)

func (c *Client) ListTasks(ctx context.Context) ([]tasks.TaskStatus, string, error) {
	var res []tasks.TaskStatus
	correlation, err := c.get(ctx, c.url().
		setPath(api.ListTasksRoute).
		build(), &res)
	return res, correlation, err
}

func (c *Client) TriggerTask(ctx context.Context, name string) (string, error) {
	var res api.TriggerTaskResponse
	correlation, err := c.post(ctx, c.url().
		setPath(api.TriggerTaskRoute).
		setPathParam("name", name).
		build(), nil, &res)
	if err != nil {
		return correlation, err
	}
	if res.Status != "triggered" {
		return correlation, fmt.Errorf("unexpected response status: %s", res.Status)
	}
	return correlation, nil
}

func (c *Client) GetTaskLogs(ctx context.Context, name string) ([]tasks.LogEntry, string, error) {
	var res []tasks.LogEntry
	correlation, err := c.get(ctx, c.url().
		setPath(api.LogsForTaskRoute).
		setPathParam("name", name).
		build(), &res)
	return res, correlation, err
}
