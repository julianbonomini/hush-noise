package noise

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// Session is a fully negotiated, bidirectional encrypted channel between two
// peers. Send and Receive are safe to call concurrently from different
// goroutines. Sessions are not resumable — if the transport dies, create a
// new Session via Dial or Accept.
type Session struct {
	conn         io.ReadWriteCloser
	sendCS       *cipherState
	recvCS       *cipherState
	remotePubKey [32]byte
	sendMu       sync.Mutex
	recvMu       sync.Mutex
	closed       bool
	closeMu      sync.Mutex
}

// Send encrypts payload and writes it to the transport with a 2-byte
// big-endian length prefix. Returns an Expected Failure error if payload
// exceeds 65535 bytes or the transport fails.
func (s *Session) Send(payload []byte) error {
	if len(payload) > maxMessageSize {
		return fmt.Errorf("noise: payload exceeds maximum message size (%d > %d)", len(payload), maxMessageSize)
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.isClosed() {
		return fmt.Errorf("noise: session is closed")
	}
	ciphertext := s.sendCS.encrypt([]byte{}, payload)
	return writeFrame(s.conn, ciphertext)
}

// Receive reads one message from the transport, decrypts it, and returns the
// plaintext. Returns an Expected Failure error on I/O or decryption failure.
func (s *Session) Receive() ([]byte, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.isClosed() {
		return nil, fmt.Errorf("noise: session is closed")
	}
	ciphertext, err := readFrame(s.conn)
	if err != nil {
		return nil, fmt.Errorf("noise: receive frame: %w", err)
	}
	plaintext, err := s.recvCS.decrypt([]byte{}, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// RemotePublicKey returns the authenticated static public key of the remote
// peer, established during the handshake. The caller is responsible for
// deciding whether to trust this identity.
func (s *Session) RemotePublicKey() []byte {
	out := make([]byte, 32)
	copy(out, s.remotePubKey[:])
	return out
}

// Close closes the underlying transport. Subsequent calls to Send or Receive
// return an error. Sessions are not resumable after Close.
func (s *Session) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.closed = true
	return s.conn.Close()
}

func (s *Session) isClosed() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

// Dial performs the XX handshake as the Initiator over conn using the provided
// Keypair. Returns a Session on success or an Expected Failure error.
// ctx cancellation is respected throughout the handshake.
func Dial(ctx context.Context, conn io.ReadWriter, keypair Keypair) (*Session, error) {
	return doHandshake(ctx, conn, keypair, true)
}

// Accept performs the XX handshake as the Responder over conn using the
// provided Keypair. Returns a Session on success or an Expected Failure error.
// ctx cancellation is respected throughout the handshake.
func Accept(ctx context.Context, conn io.ReadWriter, keypair Keypair) (*Session, error) {
	return doHandshake(ctx, conn, keypair, false)
}

// doHandshake drives the XX state machine to completion, returning a Session.
func doHandshake(ctx context.Context, conn io.ReadWriter, keypair Keypair, initiator bool) (*Session, error) {
	hs, err := newHandshakeState(keypair)
	if err != nil {
		return nil, err
	}

	// runStep runs a blocking handshake step in a goroutine and respects ctx.
	runStep := func(fn func() error) error {
		ch := make(chan error, 1)
		go func() { ch <- fn() }()
		select {
		case <-ctx.Done():
			return fmt.Errorf("noise: handshake cancelled: %w", ctx.Err())
		case err := <-ch:
			return err
		}
	}

	var sendCS, recvCS *cipherState

	if initiator {
		// -> e
		if err := runStep(func() error { return hs.writeMsg0(conn, []byte{}) }); err != nil {
			return nil, err
		}
		// <- e, ee, s, es
		if err := runStep(func() error { return hs.readMsg1(conn) }); err != nil {
			return nil, err
		}
		// -> s, se  (produces cipher states)
		var writeErr error
		if err := runStep(func() error {
			var fi, fr *cipherState
			fi, fr, writeErr = hs.writeMsg2(conn, []byte{})
			sendCS, recvCS = fi, fr
			return writeErr
		}); err != nil {
			return nil, err
		}
	} else {
		// <- e
		if err := runStep(func() error { return hs.readMsg0(conn) }); err != nil {
			return nil, err
		}
		// -> e, ee, s, es
		if err := runStep(func() error { return hs.writeMsg1(conn, []byte{}) }); err != nil {
			return nil, err
		}
		// <- s, se  (produces cipher states)
		var readErr error
		if err := runStep(func() error {
			var fi, fr *cipherState
			fi, fr, readErr = hs.readMsg2(conn)
			sendCS, recvCS = fr, fi
			return readErr
		}); err != nil {
			return nil, err
		}
	}

	// Wrap conn as ReadWriteCloser. If it already is one, use it directly.
	rwc, ok := conn.(io.ReadWriteCloser)
	if !ok {
		rwc = nopCloser{conn}
	}

	return &Session{
		conn:         rwc,
		sendCS:       sendCS,
		recvCS:       recvCS,
		remotePubKey: hs.rs,
	}, nil
}
