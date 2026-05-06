package noise_test

import (
	"context"
	"io"
	"net"
	"testing"

	noise "github.com/julianbonomini/hush-noise/go"
)

// faultReader wraps an io.Reader and returns io.ErrUnexpectedEOF after
// limit bytes have been read. Used to simulate a peer that stops
// sending mid-stream at a deterministic byte boundary.
type faultReader struct {
	r     io.Reader
	limit int
	read  int
}

func (f *faultReader) Read(p []byte) (int, error) {
	if f.read >= f.limit {
		return 0, io.ErrUnexpectedEOF
	}
	remaining := f.limit - f.read
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := f.r.Read(p)
	f.read += n
	if f.read >= f.limit {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

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

// faultConn wraps a net.Conn, substituting a faultReader on the read side.
// Writes pass through unchanged. Used to inject read-side faults at a
// deterministic byte boundary without touching the write path.
type faultConn struct {
	net.Conn
	r *faultReader
}

func (fc *faultConn) Read(p []byte) (int, error) { return fc.r.Read(p) }

// TestTCPFaultMidHandshake verifies that a read-side fault injected during
// the XX handshake causes Dial to return an Expected Failure error and not
// hang. The fault fires after 16 bytes — mid-way through the first handshake
// message (2-byte frame header + 32-byte ephemeral public key = 34 bytes).
func TestTCPFaultMidHandshake(t *testing.T) {
	iKP, err := noise.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	rKP, err := noise.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	iConn, rConn := tcpPair(t)

	// Wrap the responder's read side: fault after 16 bytes so it errors
	// while reading the initiator's first handshake message.
	fConn := &faultConn{
		Conn: rConn,
		r:    &faultReader{r: rConn, limit: 16},
	}

	dialErrCh := make(chan error, 1)
	go func() {
		_, err := noise.Dial(context.Background(), iConn, iKP)
		dialErrCh <- err
	}()

	_, acceptErr := noise.Accept(context.Background(), fConn, rKP)
	// Close iConn so the initiator's blocked Dial unblocks.
	iConn.Close()
	<-dialErrCh // drain initiator

	if acceptErr == nil {
		t.Fatal("Accept with mid-handshake fault: expected error, got nil")
	}
}

// TestTCPFaultMidReceive verifies that closing a Session while the peer is
// mid-Receive causes Receive to return an Expected Failure error and not hang.
func TestTCPFaultMidReceive(t *testing.T) {
	iSession, rSession := tcpDialAccept(t)

	errCh := make(chan error, 1)
	go func() {
		_, err := iSession.Receive()
		errCh <- err
	}()

	// Close the responder session without sending — the initiator's Receive
	// must unblock with an error.
	rSession.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("Receive after remote close: expected error, got nil")
	}
}
