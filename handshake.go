package noise

import (
	"fmt"
	"io"
)

const protocolName = "Noise_XX_25519_ChaChaPoly_BLAKE2s"

// handshakeState implements the Noise XX handshake pattern:
//
//	msg0: -> e
//	msg1: <- e, ee, s, es
//	msg2: -> s, se
//
// The initiator writes msg0, reads msg1, writes msg2.
// The responder reads msg0, writes msg1, reads msg2.
type handshakeState struct {
	ss *symmetricState
	s  Keypair  // local static keypair
	e  Keypair  // local ephemeral keypair (generated per handshake)
	rs [32]byte // remote static public key
	re [32]byte // remote ephemeral public key
}

// newHandshakeState creates a handshakeState with a freshly generated ephemeral
// keypair and empty prologue — used for production Dial/Accept.
func newHandshakeState(s Keypair) (*handshakeState, error) {
	e, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("noise: generate ephemeral keypair: %w", err)
	}
	return newHandshakeStateFixed(s, e, []byte{}), nil
}

// newHandshakeStateFixed creates a handshakeState with caller-supplied keys and
// prologue. Used by spec vector tests that require deterministic keys.
func newHandshakeStateFixed(s, e Keypair, prologue []byte) *handshakeState {
	ss := newSymmetricState(protocolName)
	ss.mixHash(prologue)
	return &handshakeState{ss: ss, s: s, e: e}
}

// writeMsg0 sends: -> e [payload]
func (hs *handshakeState) writeMsg0(w io.Writer, payload []byte) error {
	hs.ss.mixHash(hs.e.PublicKey[:])
	encPayload := hs.ss.encryptAndHash(payload)
	msg := append(hs.e.PublicKey[:], encPayload...)
	if err := writeFrame(w, msg); err != nil {
		return err
	}
	return nil
}

// readMsg0 receives: -> e [payload]
func (hs *handshakeState) readMsg0(r io.Reader) error {
	msg, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("noise: read msg0: %w", err)
	}
	if len(msg) < 32 {
		return fmt.Errorf("noise: msg0 too short: got %d bytes", len(msg))
	}
	copy(hs.re[:], msg[:32])
	hs.ss.mixHash(hs.re[:])
	if _, err := hs.ss.decryptAndHash(msg[32:]); err != nil {
		return fmt.Errorf("noise: msg0 payload: %w", err)
	}
	return nil
}

// writeMsg1 sends: <- e, ee, s, es [payload]
func (hs *handshakeState) writeMsg1(w io.Writer, payload []byte) error {
	hs.ss.mixHash(hs.e.PublicKey[:])

	eeDH, err := dh(hs.e.privateKey, hs.re)
	if err != nil {
		return fmt.Errorf("noise: ee DH: %w", err)
	}
	hs.ss.mixKey(eeDH[:])

	encS := hs.ss.encryptAndHash(hs.s.PublicKey[:])

	// es: responder's static × initiator's ephemeral
	esDH, err := dh(hs.s.privateKey, hs.re)
	if err != nil {
		return fmt.Errorf("noise: es DH: %w", err)
	}
	hs.ss.mixKey(esDH[:])

	encPayload := hs.ss.encryptAndHash(payload)

	msg := hs.e.PublicKey[:]
	msg = append(msg, encS...)
	msg = append(msg, encPayload...)
	if err := writeFrame(w, msg); err != nil {
		return err
	}
	return nil
}

// readMsg1 receives: <- e, ee, s, es [payload]
func (hs *handshakeState) readMsg1(r io.Reader) error {
	msg, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("noise: read msg1: %w", err)
	}
	if len(msg) < 32 {
		return fmt.Errorf("noise: msg1 too short")
	}

	copy(hs.re[:], msg[:32])
	hs.ss.mixHash(hs.re[:])
	msg = msg[32:]

	// ee: initiator's ephemeral × responder's ephemeral
	eeDH, err := dh(hs.e.privateKey, hs.re)
	if err != nil {
		return fmt.Errorf("noise: ee DH: %w", err)
	}
	hs.ss.mixKey(eeDH[:])

	// s (32 bytes plaintext + 16 bytes tag)
	if len(msg) < 32+tagSize {
		return fmt.Errorf("noise: msg1 missing encrypted static key")
	}
	rsEnc := msg[:32+tagSize]
	msg = msg[32+tagSize:]
	rsBytes, err := hs.ss.decryptAndHash(rsEnc)
	if err != nil {
		return err
	}
	copy(hs.rs[:], rsBytes)

	// es: initiator's ephemeral × responder's static
	esDH, err := dh(hs.e.privateKey, hs.rs)
	if err != nil {
		return fmt.Errorf("noise: es DH: %w", err)
	}
	hs.ss.mixKey(esDH[:])

	if _, err := hs.ss.decryptAndHash(msg); err != nil {
		return err
	}
	return nil
}

// writeMsg2 sends: -> s, se [payload]
// Returns the two transport CipherStates on success.
func (hs *handshakeState) writeMsg2(w io.Writer, payload []byte) (fromInitiator, fromResponder *cipherState, err error) {
	encS := hs.ss.encryptAndHash(hs.s.PublicKey[:])

	// se: initiator's static × responder's ephemeral
	seDH, err := dh(hs.s.privateKey, hs.re)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: se DH: %w", err)
	}
	hs.ss.mixKey(seDH[:])

	encPayload := hs.ss.encryptAndHash(payload)

	msg := append(encS, encPayload...)
	if err := writeFrame(w, msg); err != nil {
		return nil, nil, err
	}
	fromInitiator, fromResponder = hs.ss.split()
	return fromInitiator, fromResponder, nil
}

// readMsg2 receives: -> s, se [payload]
// Returns the two transport CipherStates on success.
func (hs *handshakeState) readMsg2(r io.Reader) (fromInitiator, fromResponder *cipherState, err error) {
	msg, err := readFrame(r)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: read msg2: %w", err)
	}

	if len(msg) < 32+tagSize {
		return nil, nil, fmt.Errorf("noise: msg2 missing encrypted static key")
	}
	rsEnc := msg[:32+tagSize]
	msg = msg[32+tagSize:]
	rsBytes, err := hs.ss.decryptAndHash(rsEnc)
	if err != nil {
		return nil, nil, err
	}
	copy(hs.rs[:], rsBytes)

	// se: responder's ephemeral × initiator's static (= DH(e_R, s_I))
	seDH, err := dh(hs.e.privateKey, hs.rs)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: se DH: %w", err)
	}
	hs.ss.mixKey(seDH[:])

	if _, err := hs.ss.decryptAndHash(msg); err != nil {
		return nil, nil, err
	}

	fromInitiator, fromResponder = hs.ss.split()
	return fromInitiator, fromResponder, nil
}
