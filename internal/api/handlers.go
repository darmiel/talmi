package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func DecodePayload(r *http.Request, dest any, allowEmpty bool) error {
	switch r.Header.Get("Content-Type") {
	case "application/json", "":
		// strict encoding for JSON
		dec := json.NewDecoder(r.Body)
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
