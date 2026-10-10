package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/protocol"
	"github.com/bpinto/foca/internal/server/core"
)

// clientMethods is everything a socket offers. None of it changes state on
// the host.
var clientMethods = map[string]bool{
	protocol.MethodHello:        true,
	protocol.MethodSecretList:   true,
	protocol.MethodSecretRead:   true,
	protocol.MethodGrantsStatus: true,
	protocol.MethodGrantsDrop:   true,
	protocol.MethodActionList:   true,
	protocol.MethodActionRun:    true,
}

// managementMethods are host CLI operations. They exist on no socket; a realm
// that asks for one is refused and the attempt is audited (design §6.2).
var managementMethods = map[string]bool{
	"secret.add": true, "secret.update": true, "secret.remove": true,
	"vault.init": true, "vault.reset": true,
	"config.reload": true, "instance.lock": true, "server.shutdown": true,
	"events.query": true, "events.subscribe": true,
}

type connState struct {
	id     string // for connection-scoped grants
	inst   *core.Instance
	peer   identity.VerifiedPeer
	client *identity.ClientInfo // from server.hello; per-request client overrides it
}

// maxPipelined is how many requests a connection may send ahead of the one
// being handled. One more closes the connection.
const maxPipelined = 4

// Reasons a connection's reader stops other than the client hanging up.
const (
	endTooLarge  = "message_too_large"
	endPipelined = "too_many_pipelined"
)

// serveConn handles requests one at a time, in order. A separate reader
// keeps reading while a request is handled, and never waits for the handler,
// so a client that hangs up is noticed at once even if it sent more
// requests: its pending prompt is cancelled instead of holding a queue slot
// until prompt_timeout, and requests it left queued aren't handled. A
// connection that sends no complete request within IdleTimeout is closed;
// the deadline is lifted while a request is being handled, so a slow
// approval never trips it.
func (s *Server) serveConn(conn *net.UnixConn, inst *core.Instance) {
	peer, ok := s.admit(conn, inst)
	if !ok {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	st := &connState{id: ids.New(), inst: inst, peer: peer}
	msgs := make(chan []byte, maxPipelined)
	ended := make(chan string, 1)
	go s.readLoop(conn, cancel, msgs, ended)
	conn.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
	for line := range msgs {
		if ctx.Err() != nil {
			// Nobody is left to answer. The request is recorded, not handled.
			s.reject(inst, "connection_closed", &peer)
			continue
		}
		conn.SetReadDeadline(time.Time{})
		if resp := s.handle(ctx, st, line); resp != nil && !s.write(conn, *resp) {
			// The client isn't taking answers. Closing ends the reader,
			// and what it left queued is recorded below.
			cancel()
			conn.Close()
			continue
		}
		conn.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
	}
	switch <-ended {
	case endTooLarge:
		call := core.Call{RequestID: ids.New(), Origin: audit.OriginClientSocket, Conn: st.id, Instance: inst, Peer: peer, Reported: st.client}
		s.write(conn, *s.refuseAs(ctx, call, nil, "", endTooLarge,
			protocol.NewError(protocol.CodeParseError, "message too large (max %d bytes)", protocol.MaxMessage)))
	case endPipelined:
		s.reject(inst, endPipelined, &peer)
	}
}

// readLoop frames messages until the connection fails, then cancels the
// connection's in-flight work and reports why it stopped ("" for a hang-up
// or a read error). It never blocks on the handler: a request beyond
// maxPipelined waiting ones closes the connection. EOF counts as hanging up,
// so clients must not half-close while they wait for an answer.
func (s *Server) readLoop(conn *net.UnixConn, cancel context.CancelFunc, msgs chan<- []byte, ended chan<- string) {
	reason := ""
	defer func() {
		cancel()
		ended <- reason
		close(msgs)
	}()
	r := bufio.NewReaderSize(conn, 64*1024)
	for {
		line, err := protocol.ReadMessage(r)
		if errors.Is(err, protocol.ErrTooLarge) {
			reason = endTooLarge
			return
		}
		if err != nil {
			return
		}
		select {
		case msgs <- line:
		default:
			// The handler may be stuck writing to a client that doesn't
			// read; closing the connection unblocks it.
			reason = endPipelined
			conn.Close()
			return
		}
	}
}

func (s *Server) handle(ctx context.Context, st *connState, line []byte) *protocol.Response {
	call := core.Call{RequestID: ids.New(), Origin: audit.OriginClientSocket, Conn: st.id, Instance: st.inst, Peer: st.peer, Reported: st.client}
	if !json.Valid(line) {
		return s.refuse(ctx, call, nil, "", protocol.NewError(protocol.CodeParseError, "invalid JSON"))
	}
	req, err := protocol.DecodeRequest(line)
	if err != nil {
		return s.refuse(ctx, call, nil, "", protocol.NewError(protocol.CodeInvalidRequest, "%v", err))
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return s.refuse(ctx, call, req.ID, req.Method, protocol.NewError(protocol.CodeInvalidRequest, "not a JSON-RPC 2.0 request"))
	}
	if len(req.ID) == 0 {
		// Notifications aren't part of this protocol; there is nothing to
		// answer them with, but the attempt is still recorded.
		s.refuse(ctx, call, nil, req.Method, protocol.NewError(protocol.CodeInvalidRequest, "notifications are not supported"))
		return nil
	}
	if managementMethods[req.Method] {
		return s.refuseAs(ctx, call, req.ID, req.Method, "forbidden_on_socket",
			protocol.NewError(protocol.CodeForbiddenOnSocket, "%s is a host CLI operation; it is not available on any socket", req.Method))
	}
	if !clientMethods[req.Method] {
		return s.refuse(ctx, call, req.ID, req.Method, protocol.NewError(protocol.CodeMethodNotFound, "unknown method %q", safeMethod(req.Method)))
	}

	result, perr := s.dispatch(ctx, st, call, req)
	if perr != nil {
		if rejectionCodes[perr.Code] && perr.Data.EventSeq == 0 {
			// Refused before the core recorded anything: record it here.
			return s.refuse(ctx, call, req.ID, req.Method, perr)
		}
		return errResp(req.ID, perr)
	}
	b, err := protocol.Marshal(result)
	if err != nil {
		return errResp(req.ID, protocol.NewError(protocol.CodeInternal, "encoding failed"))
	}
	return &protocol.Response{JSONRPC: "2.0", ID: req.ID, Result: b}
}

// rejectionCodes are refusals of the request itself. Each is audited as
// request.rejected (design §8.2), so a realm probing the socket is visible.
var rejectionCodes = map[int]bool{
	protocol.CodeParseError:          true,
	protocol.CodeInvalidRequest:      true,
	protocol.CodeMethodNotFound:      true,
	protocol.CodeInvalidParams:       true,
	protocol.CodeProtocolUnsupported: true,
}

// refuse records a rejected request and returns the error response. The
// reason is the error's own, else its code's name. If it can't be recorded,
// the answer becomes audit_failed, as for every other unrecorded request.
func (s *Server) refuse(ctx context.Context, call core.Call, id json.RawMessage, method string, pe *protocol.Error) *protocol.Response {
	reason := pe.Data.Reason
	if reason == "" {
		reason = protocol.CodeName(pe.Code)
	}
	return s.refuseAs(ctx, call, id, method, reason, pe)
}

func (s *Server) refuseAs(ctx context.Context, call core.Call, id json.RawMessage, method, reason string, pe *protocol.Error) *protocol.Response {
	e := s.opts.Core.Event(call, audit.TypeRequestRejected, audit.OutcomeRejected)
	e.Reason = reason
	if method != "" {
		e.Params = map[string]string{"method": safeMethod(method)}
	}
	seq, err := s.opts.Core.RecordRejection(ctx, e)
	if err != nil {
		return errResp(id, protocol.NewError(protocol.CodeAuditFailed, "could not record the request; refusing it"))
	}
	pe.Data.RequestID, pe.Data.EventSeq = call.RequestID, seq
	return errResp(id, pe)
}

// safeMethod bounds a caller-supplied method name before it is stored or
// echoed: method-name characters only, at most 64 bytes.
func safeMethod(m string) string {
	b := []byte(m)
	if len(b) > 64 {
		b = b[:64]
	}
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			b[i] = '?'
		}
	}
	return string(b)
}

// decode applies strict decoding and the per-request common fields.
func (s *Server) decode(st *connState, call *core.Call, raw json.RawMessage, v protocol.Params) *protocol.Error {
	if err := protocol.DecodeParams(raw, v); err != nil {
		return protocol.NewError(protocol.CodeInvalidParams, "%v", err)
	}
	base := v.Base()
	if base.MinProtocol > protocol.Version {
		return protocol.NewError(protocol.CodeProtocolUnsupported,
			"client needs protocol %d; this server speaks %d", base.MinProtocol, protocol.Version)
	}
	if base.Client != nil {
		c := base.Client.Clean()
		call.Reported = &c
	}
	return nil
}

func (s *Server) dispatch(ctx context.Context, st *connState, call core.Call, req protocol.Request) (any, *protocol.Error) {
	switch req.Method {
	case protocol.MethodHello:
		var p protocol.HelloParams
		if e := s.decode(st, &call, req.Params, &p); e != nil {
			return nil, e
		}
		if call.Reported != nil {
			st.client = call.Reported
		}
		return protocol.HelloResult{
			Protocol: protocol.Version, Instance: st.inst.Name, Realm: st.inst.Realm,
			ServerVersion: s.opts.Version, Features: features,
		}, nil

	case protocol.MethodSecretList:
		var p protocol.SecretListParams
		if e := s.decode(st, &call, req.Params, &p); e != nil {
			return nil, e
		}
		rs, err := s.opts.Core.ListSecrets(ctx, call)
		if err != nil {
			return nil, asProtocol(err)
		}
		out := protocol.SecretListResult{Secrets: []protocol.SecretInfo{}}
		for _, r := range rs {
			info := protocol.SecretInfo{Name: r.Ref.ID, Description: r.Description}
			if r.Ref.Display != r.Ref.ID {
				info.DisplayName = r.Ref.Display
			}
			out.Secrets = append(out.Secrets, info)
		}
		return out, nil

	case protocol.MethodSecretRead:
		var p protocol.SecretReadParams
		if e := s.decode(st, &call, req.Params, &p); e != nil {
			return nil, e
		}
		secrets, err := s.opts.Core.ReadSecrets(ctx, call, p.Names)
		if err != nil {
			return nil, asProtocol(err)
		}
		defer core.ZeroSecrets(secrets)
		out := protocol.SecretReadResult{}
		for _, sec := range secrets {
			v, enc := protocol.EncodeValue(sec.Value)
			out.Secrets = append(out.Secrets, protocol.SecretOut{Name: sec.Name, Value: v, Encoding: enc})
		}
		return out, nil

	case protocol.MethodGrantsStatus:
		var p protocol.GrantsStatusParams
		if e := s.decode(st, &call, req.Params, &p); e != nil {
			return nil, e
		}
		gs, err := s.opts.Core.Grants(ctx, call)
		if err != nil {
			return nil, asProtocol(err)
		}
		out := protocol.GrantsStatusResult{Grants: []protocol.GrantInfo{}}
		for _, g := range gs {
			out.Grants = append(out.Grants, protocol.GrantInfo{Name: g.Resource.ID, Kind: g.Resource.Kind, Params: g.Params, Scope: g.Scope, ApprovalID: g.ApprovalID, ExpiresAt: g.ExpiresAt})
		}
		return out, nil

	case protocol.MethodGrantsDrop:
		var p protocol.GrantsDropParams
		if e := s.decode(st, &call, req.Params, &p); e != nil {
			return nil, e
		}
		n, err := s.opts.Core.DropGrants(ctx, call, p.Names)
		if err != nil {
			return nil, asProtocol(err)
		}
		return protocol.GrantsDropResult{Dropped: n}, nil

	case protocol.MethodActionList:
		var p protocol.ActionListParams
		if e := s.decode(st, &call, req.Params, &p); e != nil {
			return nil, e
		}
		rs, err := s.opts.Core.ListActions(ctx, call)
		if err != nil {
			return nil, asProtocol(err)
		}
		out := protocol.ActionListResult{Actions: []protocol.ActionInfo{}}
		for _, r := range rs {
			info := protocol.ActionInfo{Name: r.Ref.ID, Description: r.Description, Params: []protocol.ParamSchema{}}
			for _, pa := range r.Params {
				info.Params = append(info.Params, protocol.ParamSchema{Name: pa.Name, Description: pa.Description,
					Allowed: pa.Allowed, Pattern: pa.Pattern, AllowLeadingDash: pa.AllowLeadingDash})
			}
			out.Actions = append(out.Actions, info)
		}
		return out, nil

	case protocol.MethodActionRun:
		var p protocol.ActionRunParams
		if e := s.decode(st, &call, req.Params, &p); e != nil {
			return nil, e
		}
		o, err := s.opts.Core.RunAction(ctx, call, p.Name, p.Params)
		if err != nil {
			return nil, asProtocol(err)
		}
		defer o.Zero()
		out := protocol.ActionRunResult{ExitCode: o.ExitCode}
		if o.Stdout != nil {
			out.Stdout, out.StdoutEncoding = protocol.EncodeValue(o.Stdout)
		}
		if len(o.StderrTail) > 0 {
			out.StderrTail, out.StderrEncoding = protocol.EncodeValue(o.StderrTail)
		}
		return out, nil
	}
	return nil, protocol.NewError(protocol.CodeMethodNotFound, "unknown method %q", req.Method)
}

func asProtocol(err error) *protocol.Error {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe
	}
	return protocol.NewError(protocol.CodeInternal, "internal error")
}

func errResp(id json.RawMessage, e *protocol.Error) *protocol.Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &protocol.Response{JSONRPC: "2.0", ID: id, Error: e}
}

// write sends one response and zeroes the encoded bytes afterwards, since
// they may contain secret values. A client that doesn't read its answer
// within WriteTimeout is given up on: false means the connection must close.
// The core refuses values that wouldn't fit before it records them served;
// any other answer too large to read is replaced by an error, so the client
// isn't left with a connection that fails mid-message.
func (s *Server) write(conn net.Conn, resp protocol.Response) bool {
	b, err := protocol.Marshal(resp)
	if err != nil {
		return false
	}
	if len(b) > protocol.MaxMessage {
		zero(b)
		zero(resp.Result)
		s.opts.Log.Warn("answer too large for one message; sent an error instead", "bytes", len(b))
		b, err = protocol.Marshal(errResp(resp.ID, protocol.NewError(protocol.CodeInternal, "the answer is larger than one message (%d bytes)", protocol.MaxMessage)))
		if err != nil {
			return false
		}
	}
	b = append(b, '\n')
	conn.SetWriteDeadline(time.Now().Add(s.opts.WriteTimeout))
	_, err = conn.Write(b)
	zero(b)
	zero(resp.Result)
	return err == nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// features are the methods server.hello advertises.
var features = []string{protocol.MethodSecretList, protocol.MethodSecretRead, protocol.MethodGrantsStatus,
	protocol.MethodGrantsDrop, protocol.MethodActionList, protocol.MethodActionRun}
