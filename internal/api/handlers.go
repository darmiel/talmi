package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func DecodePayload(w http.ResponseWriter, r *http.Request, dest any, allowEmpty bool) error {
	switch r.Header.Get("Content-Type") {
	case "application/json", "":
		// strict encoding for JSON
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dest); err != nil {
			if !errors.Is(err, io.EOF) || !allowEmpty {
				return err
			}
		}
		// ensure there's no extra data
		if dec.More() {
			return errors.New("extra data in request body")
		}
		return nil
	default:
		return errors.New("unsupported content type")
	}
}
