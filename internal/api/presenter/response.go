package presenter

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/darmiel/talmi/internal/service"
)

type ErrorResponse struct {
	Error         string `json:"error"`
	CorrelationID string `json:"correlation_id"`
}

func JSON(w http.ResponseWriter, r *http.Request, data any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to write json response")
	}
}

func Error(w http.ResponseWriter, r *http.Request, msg string, status int) {
	correlationID, _ := r.Context().Value("correlation_id").(string)
	resp := ErrorResponse{
		Error:         msg,
		CorrelationID: correlationID,
	}
	JSON(w, r, resp, status)
}

func Err(w http.ResponseWriter, r *http.Request, err error, short string) {
	status := http.StatusBadRequest // generic default status
	var httpError service.HTTPError
	if errors.As(err, &httpError) {
		status = httpError.StatusCode
	}
	Error(w, r, short+": "+err.Error(), status)
}
