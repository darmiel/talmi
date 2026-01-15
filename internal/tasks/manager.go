package tasks

import (
	"sync"
	"time"
)

const MaxLogsPerTask = 1000

type Manager struct {
	tasks sync.Map
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) Register(name string, interval time.Duration, fn TaskFunc) {
	task := &RunnableTask{
		Name:     name,
		Interval: interval,
		Handler:  fn,
		Logs:     make([]LogEntry, 0),
	}
	m.tasks.Store(name, task)

	if interval > 0 {
		// TODO: more robust scheduling
		go m.scheduler(task)
	}
}

func (m *Manager) Trigger(name string) error {
	t, ok := m.tasks.Load(name)
	if !ok {
		return TaskNotFoundError{Name: name}
	}
	task := t.(*RunnableTask)
	go task.Run()
	return nil
}

func (m *Manager) ListStatus() []TaskStatus {
	var list []TaskStatus
	m.tasks.Range(func(key, value any) bool {
		task := value.(*RunnableTask)
		list = append(list, task.Status())
		return true
	})
	return list
}

func (m *Manager) GetLogs(name string) ([]LogEntry, error) {
	t, ok := m.tasks.Load(name)
	if !ok {
		return nil, TaskNotFoundError{Name: name}
	}
	task := t.(*RunnableTask)
	return task.GetLogs(), nil
}

func (m *Manager) scheduler(task *RunnableTask) {
	ticker := time.NewTicker(task.Interval)
	for range ticker.C {
		task.Run()
	}
}
