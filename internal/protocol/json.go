package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Read bounds protocol input and allows cancellation while waiting for EOF.
// The caller must close stdin or exit the process to release a pending read.
func Read(ctx context.Context, stdin io.Reader, limit int) ([]byte, error) {
	type result struct {
		input []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		input, err := io.ReadAll(io.LimitReader(stdin, int64(limit)+1))
		done <- result{input, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		if len(result.input) > limit {
			clear(result.input)
			return nil, fmt.Errorf("input exceeds the %d MiB limit", limit/(1024*1024))
		}
		return result.input, result.err
	}
}

// Decode accepts exactly one JSON value.
func Decode(input []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			err = errors.New("unexpected trailing JSON data")
		}
		return err
	}
	return nil
}

// Object decodes exact field names and rejects duplicates, including escaped
// duplicates, rather than encoding/json's case-insensitive struct matching.
func Object(input []byte, fields map[string]any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("input must be a JSON object")
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name := token.(string)
		target, ok := fields[name]
		if !ok {
			return fmt.Errorf("unknown field %q", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = true
		if err := decoder.Decode(target); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
