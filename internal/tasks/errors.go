package tasks

import "fmt"

type TaskNotFoundError struct {
	Name string
}

func (e TaskNotFoundError) Error() string {
	return fmt.Sprintf("task '%s' not found", e.Name)
}
