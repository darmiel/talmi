package tasks

import (
	"context"
	"sync"
	"time"
)

const MaxLogsPerTask = 1000

type Manager struct {
	ctx   context.Context
	tasks sync.Map
	wg    sync.WaitGroup
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{
		ctx: ctx,
	}
}

func (m *Manager) Register(name string, interval time.Duration, fn TaskFunc) {
	task := &RunnableTask{
		Name:         name,
		Interval:     interval,
		Handler:      fn,
		Logs:         make([]LogEntry, 0),
		registeredAt: time.Now(),
	}
	m.tasks.Store(name, task)

	if interval > 0 {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.scheduler(task)
		}()
	}
}

func (m *Manager) scheduler(task *RunnableTask) {
	ticker := time.NewTicker(task.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			task.Run(m.ctx)
		}
	}
}

// Trigger runs a task once, regardless of its interval.
func (m *Manager) Trigger(name string) error {
	t, ok := m.tasks.Load(name)
	if !ok {
		return TaskNotFoundError{Name: name}
	}
	task, ok := t.(*RunnableTask)
	if !ok {
		return TaskNotFoundError{Name: name}
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		task.Run(m.ctx)
	}()
	return nil
}

// Wait blocks until all scheduler loops and in-flight runs have stopped.
func (m *Manager) Wait() {
	m.wg.Wait()
}

func (m *Manager) ListStatus() []TaskStatus {
	var list []TaskStatus
	m.tasks.Range(func(_, value any) bool {
		if rt, ok := value.(*RunnableTask); ok {
			list = append(list, rt.Status())
		}
		return true
	})
	return list
}

func (m *Manager) GetLogs(name string) ([]LogEntry, error) {
	t, ok := m.tasks.Load(name)
	if !ok {
		return nil, TaskNotFoundError{Name: name}
	}
	rt, ok := t.(*RunnableTask)
	if !ok {
		return nil, TaskNotFoundError{Name: name}
	}
	return rt.GetLogs(), nil
}
