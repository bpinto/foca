package protocol

import "fmt"

// Error codes. Standard JSON-RPC codes plus foca's own range.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603

	CodeDenied              = -32001
	CodeNotFound            = -32002
	CodeNotInitialized      = -32003
	CodeAuthUnavailable     = -32004
	CodeTimeout             = -32005
	CodeBusy                = -32006
	CodeAuditFailed         = -32007
	CodeParamRejected       = -32008
	CodeForbiddenOnSocket   = -32010
	CodeProtocolUnsupported = -32011
)

var codeNames = map[int]string{
	CodeParseError:          "parse_error",
	CodeInvalidRequest:      "invalid_request",
	CodeMethodNotFound:      "method_not_found",
	CodeInvalidParams:       "invalid_params",
	CodeInternal:            "internal",
	CodeDenied:              "denied",
	CodeNotFound:            "not_found",
	CodeNotInitialized:      "not_initialized",
	CodeAuthUnavailable:     "auth_unavailable",
	CodeTimeout:             "timeout",
	CodeBusy:                "busy",
	CodeAuditFailed:         "audit_failed",
	CodeParamRejected:       "param_rejected",
	CodeForbiddenOnSocket:   "forbidden_on_socket",
	CodeProtocolUnsupported: "protocol_unsupported",
}

// CodeName returns the stable snake_case name for a code.
func CodeName(code int) string {
	if n, ok := codeNames[code]; ok {
		return n
	}
	return "error"
}

type Error struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Data    *ErrorData `json:"data,omitempty"`
}

type ErrorData struct {
	Name      string `json:"name"`
	RequestID string `json:"request_id,omitempty"`
	EventSeq  uint64 `json:"event_seq,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", CodeName(e.Code), e.Message)
}

// NewError builds an error whose data always carries the code name.
func NewError(code int, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Data: &ErrorData{Name: CodeName(code)}}
}
