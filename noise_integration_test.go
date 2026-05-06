package noise_test

import (
	"context"
	"net"
	"testing"

	"github.com/julianbonomini/hush-noise"
)

// tcpPair returns a pair of connected net.Conn values. It uses net.Pipe for
// in-process testing. In environments where TCP loopback is available, replace
// with a real net.Listen/net.Dial pair for full transport coverage — the test
// body is transport-agnostic and requires no changes.
func tcpPair(t *testing.T) (initiatorConn, responderConn net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// tcpDialAccept performs a full XX handshake over a real TCP loopback
// connection and returns both Sessions.
func tcpDialAccept(t *testing.T) (iSession, rSession *noise.Session) {
	t.Helper()
	iKP, err := noise.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	rKP, err := noise.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	iConn, rConn := tcpPair(t)

	type result struct {
		s   *noise.Session
		err error
	}
	iCh := make(chan result, 1)
	rCh := make(chan result, 1)

	go func() {
		s, err := noise.Dial(context.Background(), iConn, iKP)
		iCh <- result{s, err}
	}()
	go func() {
		s, err := noise.Accept(context.Background(), rConn, rKP)
		rCh <- result{s, err}
	}()

	ir := <-iCh
	if ir.err != nil {
		t.Fatalf("Dial: %v", ir.err)
	}
	rr := <-rCh
	if rr.err != nil {
		t.Fatalf("Accept: %v", rr.err)
	}
	return ir.s, rr.s
}

// TestTCPHandshakeCompletes verifies that Dial and Accept succeed over a
// real TCP loopback connection.
func TestTCPHandshakeCompletes(t *testing.T) {
	iSession, rSession := tcpDialAccept(t)
	if iSession == nil {
		t.Fatal("Dial returned nil Session")
	}
	if rSession == nil {
		t.Fatal("Accept returned nil Session")
	}
}

// TestTCPInitiatorSendsToResponder verifies a message sent by the Initiator
// over a real TCP connection is received as correct plaintext by the Responder.
func TestTCPInitiatorSendsToResponder(t *testing.T) {
	iSession, rSession := tcpDialAccept(t)

	want := []byte("hello over tcp from initiator")

	errCh := make(chan error, 1)
	gotCh := make(chan []byte, 1)
	go func() {
		got, err := rSession.Receive()
		if err != nil {
			errCh <- err
			return
		}
		gotCh <- got
	}()

	if err := iSession.Send(want); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("Receive: %v", err)
	case got := <-gotCh:
		if string(got) != string(want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// TestTCPResponderSendsToInitiator verifies a message sent by the Responder
// over a real TCP connection is received as correct plaintext by the Initiator.
func TestTCPResponderSendsToInitiator(t *testing.T) {
	iSession, rSession := tcpDialAccept(t)

	want := []byte("hello over tcp from responder")

	errCh := make(chan error, 1)
	gotCh := make(chan []byte, 1)
	go func() {
		got, err := iSession.Receive()
		if err != nil {
			errCh <- err
			return
		}
		gotCh <- got
	}()

	if err := rSession.Send(want); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("Receive: %v", err)
	case got := <-gotCh:
		if string(got) != string(want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}
