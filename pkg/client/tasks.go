package client

import (
	"context"
	"fmt"

	"github.com/darmiel/talmi/internal/api"
	"github.com/darmiel/talmi/internal/tasks"
)

func (c *Client) ListTasks(ctx context.Context) ([]tasks.TaskStatus, error) {
	var res []tasks.TaskStatus
	err := c.get(ctx, c.url().
		setPath(api.ListTasksRoute).
		build(), &res)
	return res, err
}

func (c *Client) TriggerTask(ctx context.Context, name string) error {
	var res api.TriggerTaskResponse
	err := c.post(ctx, c.url().
		setPath(api.TriggerTaskRoute).
		setPathParam("name", name).
		build(), nil, &res)
	if err != nil {
		return err
	}
	if res.Status != "triggered" {
		return fmt.Errorf("unexpected response status: %s", res.Status)
	}
	return nil
}

func (c *Client) GetTaskLogs(ctx context.Context, name string) ([]tasks.LogEntry, error) {
	var res []tasks.LogEntry
	err := c.get(ctx, c.url().
		setPath(api.LogsForTaskRoute).
		setPathParam("name", name).
		build(), &res)
	return res, err
}
