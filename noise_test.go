package noise_test

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/julianbonomini/hush-noise"
)

// generateKeypair is a test helper — keypair generation is the caller's
// responsibility, but we need valid keypairs to exercise the library.
func generateKeypair(t *testing.T) noise.Keypair {
	t.Helper()
	kp, err := noise.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return kp
}

// pipe returns a pair of connected net.Conn values backed by an in-process
// net.Pipe — no network required.
func pipe(t *testing.T) (initiatorConn, responderConn net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// dialAccept performs a full XX handshake concurrently and returns both Sessions.
// Safe to use because Dial and Accept run in separate goroutines and the pipe
// is drained before both sessions are returned.
func dialAccept(t *testing.T) (iSession, rSession *noise.Session) {
	t.Helper()
	iKP := generateKeypair(t)
	rKP := generateKeypair(t)
	iConn, rConn := pipe(t)

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

// dialAcceptWithKeys returns both Sessions and both static Keypairs.
func dialAcceptWithKeys(t *testing.T) (iSession, rSession *noise.Session, iKP, rKP noise.Keypair) {
	t.Helper()
	iKP = generateKeypair(t)
	rKP = generateKeypair(t)
	iConn, rConn := pipe(t)

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
	return ir.s, rr.s, iKP, rKP
}

// TestHandshakeCompletes is the tracer bullet: Initiator dials, Responder
// accepts, both receive a non-nil Session without error.
func TestHandshakeCompletes(t *testing.T) {
	iSession, rSession := dialAccept(t)
	if iSession == nil {
		t.Fatal("Dial returned nil Session")
	}
	if rSession == nil {
		t.Fatal("Accept returned nil Session")
	}
}

// TestInitiatorSendsToResponder verifies that a message sent by the Initiator
// is received as correct plaintext by the Responder.
func TestInitiatorSendsToResponder(t *testing.T) {
	iSession, rSession := dialAccept(t)

	want := []byte("hello from initiator")

	gotCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
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
		if !bytes.Equal(got, want) {
			t.Fatalf("Receive: got %q, want %q", got, want)
		}
	}
}

// TestResponderSendsToInitiator verifies that a message sent by the Responder
// is received as correct plaintext by the Initiator.
func TestResponderSendsToInitiator(t *testing.T) {
	iSession, rSession := dialAccept(t)

	want := []byte("hello from responder")

	gotCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
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
		if !bytes.Equal(got, want) {
			t.Fatalf("Receive: got %q, want %q", got, want)
		}
	}
}

// TestRemotePublicKey verifies that each peer's RemotePublicKey matches the
// other peer's static public key.
func TestRemotePublicKey(t *testing.T) {
	iSession, rSession, iKP, rKP := dialAcceptWithKeys(t)

	if !bytes.Equal(iSession.RemotePublicKey(), rKP.PublicKey[:]) {
		t.Errorf("initiator RemotePublicKey = %x, want responder's %x",
			iSession.RemotePublicKey(), rKP.PublicKey)
	}
	if !bytes.Equal(rSession.RemotePublicKey(), iKP.PublicKey[:]) {
		t.Errorf("responder RemotePublicKey = %x, want initiator's %x",
			rSession.RemotePublicKey(), iKP.PublicKey)
	}
}

// TestSendReceiveConcurrent verifies Send and Receive are safe to call
// concurrently from different goroutines.
func TestSendReceiveConcurrent(t *testing.T) {
	iSession, rSession := dialAccept(t)

	const n = 50
	var wg sync.WaitGroup

	// Initiator sends n messages; Responder receives them.
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if err := iSession.Send([]byte("ping")); err != nil {
				t.Errorf("Send: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if _, err := rSession.Receive(); err != nil {
				t.Errorf("Receive: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

// TestSendOversizePayload verifies that Send returns an error for payloads
// exceeding the Noise spec maximum of 65535 bytes.
func TestSendOversizePayload(t *testing.T) {
	iSession, _ := dialAccept(t)

	oversized := make([]byte, 65536)
	err := iSession.Send(oversized)
	if err == nil {
		t.Fatal("Send with 65536-byte payload: expected error, got nil")
	}
}

// TestCloseSessionRejectsSubsequentSend verifies that Close causes Send to
// return an error.
func TestCloseSessionRejectsSubsequentSend(t *testing.T) {
	iSession, _ := dialAccept(t)

	if err := iSession.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := iSession.Send([]byte("after close")); err == nil {
		t.Fatal("Send after Close: expected error, got nil")
	}
}

// TestCloseSessionRejectsSubsequentReceive verifies that Close causes Receive
// to return an error.
func TestCloseSessionRejectsSubsequentReceive(t *testing.T) {
	iSession, _ := dialAccept(t)

	if err := iSession.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := iSession.Receive(); err == nil {
		t.Fatal("Receive after Close: expected error, got nil")
	}
}

// TestContextCancellationDuringHandshake verifies that a cancelled context
// causes Dial/Accept to return an error without hanging.
func TestContextCancellationDuringHandshake(t *testing.T) {
	iKP := generateKeypair(t)
	_, rConn := pipe(t) // iConn deliberately unused — nobody dials

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := noise.Accept(ctx, rConn, iKP)
	if err == nil {
		t.Fatal("Accept with cancelled context: expected error, got nil")
	}
}
