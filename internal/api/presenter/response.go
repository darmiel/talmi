package presenter

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
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
