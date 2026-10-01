// Package protocol is the wire contract shared by the service and its
// clients: newline-delimited JSON-RPC 2.0 over a Unix stream socket.
//
// Clients (the CLI, the relay) import only this package and internal/client,
// never anything from the service side.
package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
)

// Version is the protocol version spoken by this build.
const Version = 1

// MaxMessage is the largest accepted message, excluding the newline.
const MaxMessage = 1 << 20

var ErrTooLarge = errors.New("message too large")

// MaxID bounds a request's id as written. An answer echoes the id, so this
// bounds what the id adds to it.
const MaxID = 64

// MaxResult is the most a result may take when encoded, so that its answer,
// whatever the request's id, fits in one message.
const MaxResult = MaxMessage - len(`{"jsonrpc":"2.0","id":,"result":}`) - MaxID

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Notification is a server-to-client message without an id (events.subscribe).
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

var requestType = reflect.TypeOf(Request{})

// DecodeRequest decodes one request envelope strictly: exact-case keys and no
// duplicates, so a relay and the host can't read the method or id
// differently. Params are checked against their own type by DecodeParams.
// A request without an id is a notification.
func DecodeRequest(line []byte) (Request, error) {
	var req Request
	if err := CheckStrict(line, requestType); err != nil {
		return req, err
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return req, err
	}
	if len(req.ID) > 0 {
		if err := checkID(req.ID); err != nil {
			// Not echoed: the answer's id is null.
			req.ID = nil
			return req, err
		}
	}
	return req, nil
}

// checkID allows the ids JSON-RPC 2.0 recommends: a string, or a number
// without a fraction, here an int64. Anything else (null, an object, 1e999)
// is refused, as is an id longer than MaxID.
func checkID(id json.RawMessage) error {
	if len(id) > MaxID {
		return fmt.Errorf("id longer than %d bytes", MaxID)
	}
	if id[0] == '"' {
		return nil
	}
	if _, err := strconv.ParseInt(string(id), 10, 64); err != nil {
		return errors.New("id must be a string or an integer")
	}
	return nil
}

// ReadMessage reads one newline-terminated message. A message longer than
// MaxMessage returns ErrTooLarge; the stream should then be closed, because
// the rest of the oversized line is still unread.
func ReadMessage(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		chunk, err := r.ReadSlice('\n')
		if buf.Len()+len(chunk) > MaxMessage+1 {
			return nil, ErrTooLarge
		}
		buf.Write(chunk)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF && buf.Len() > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
	}
}

// Marshal encodes v as a message, without the newline. Unlike json.Marshal
// it leaves <, > and & as they are: escaped, each takes six bytes, so a
// message could grow far past what was checked to fit.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// WriteMessage encodes v as one line.
func WriteMessage(w io.Writer, v any) error {
	b, err := Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// DecodeParams decodes params strictly: unknown fields are an error, because
// silently dropping a field a client relies on for enforcement fails open.
// Empty params decode as an empty object.
func DecodeParams(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		raw = []byte("{}")
	}
	if err := CheckStrict(raw, reflect.TypeOf(v)); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	if dec.More() {
		return errors.New("invalid params: trailing data")
	}
	return nil
}
