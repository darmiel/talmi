package service

// HTTPError represents an error with an associated HTTP status code.
// TODO(future): it is probably not optimal to tie service errors to HTTP layer. We should refactor this later. :)
type HTTPError struct {
	StatusCode int
	Wrapped    error
}

func (e HTTPError) Error() string {
	return e.Wrapped.Error()
}

func (e HTTPError) Unwrap() error {
	return e.Wrapped
}

func httpError(statusCode int, err error) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Wrapped:    err,
	}
}
