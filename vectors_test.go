package noise

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"testing"
)

// cacophonyFile is the shape of testdata/cacophony.json.
// Source: https://github.com/mcginty/snow/blob/master/tests/vectors/cacophony.txt
// Filtered to Noise_XX_25519_ChaChaPoly_BLAKE2s only.
type cacophonyFile struct {
	Vectors []cacophonyVector `json:"vectors"`
}

// cacophonyVector is the shape of one entry in the cacophony test vector file.
type cacophonyVector struct {
	ProtocolName  string `json:"protocol_name"`
	InitPrologue  string `json:"init_prologue"`
	InitStatic    string `json:"init_static"`
	InitEphemeral string `json:"init_ephemeral"`
	RespPrologue  string `json:"resp_prologue"`
	RespStatic    string `json:"resp_static"`
	RespEphemeral string `json:"resp_ephemeral"`
	HandshakeHash string `json:"handshake_hash"`
	Messages      []struct {
		Payload    string `json:"payload"`
		Ciphertext string `json:"ciphertext"`
	} `json:"messages"`
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func keypairFromPrivHex(t *testing.T, privHex string) Keypair {
	t.Helper()
	priv := mustDecodeHex(t, privHex)

	var kp Keypair
	copy(kp.PrivateKey[:], priv)
	pub, err := derivePublicKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	kp.PublicKey = pub
	return kp
}

// TestSpecVectors verifies the implementation against every vector in
// testdata/cacophony.json for Noise_XX_25519_ChaChaPoly_BLAKE2s.
//
// Passing these vectors proves spec-compliance, not just self-consistency:
// the expected ciphertexts and handshake hashes were produced by an independent
// implementation (cacophony) against the Noise Protocol spec.
func TestSpecVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/cacophony.json")
	if err != nil {
		t.Fatalf("read testdata/cacophony.json: %v", err)
	}
	var file cacophonyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse cacophony.json: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("cacophony.json contains no vectors")
	}

	for _, vec := range file.Vectors {
		vec := vec
		t.Run(vec.ProtocolName, func(t *testing.T) {
			runCacophonyVector(t, vec)
		})
	}
}

func runCacophonyVector(t *testing.T, vec cacophonyVector) {
	t.Helper()

	initStatic := keypairFromPrivHex(t, vec.InitStatic)
	initEphemeral := keypairFromPrivHex(t, vec.InitEphemeral)
	respStatic := keypairFromPrivHex(t, vec.RespStatic)
	respEphemeral := keypairFromPrivHex(t, vec.RespEphemeral)
	prologue := mustDecodeHex(t, vec.InitPrologue) // same for both sides per vector

	iConn, rConn := net.Pipe()
	defer iConn.Close()
	defer rConn.Close()

	type result struct {
		cs   [2]*cipherState
		hash [32]byte
		err  error
	}

	iCh := make(chan result, 1)
	rCh := make(chan result, 1)

	go func() {
		hs := newHandshakeStateFixed(initStatic, initEphemeral, prologue)
		if err := hs.writeMsg0(iConn, mustDecodeHex(t, vec.Messages[0].Payload)); err != nil {
			iCh <- result{err: err}
			return
		}
		if err := hs.readMsg1(iConn); err != nil {
			iCh <- result{err: err}
			return
		}
		c1, c2, err := hs.writeMsg2(iConn, mustDecodeHex(t, vec.Messages[2].Payload))
		if err != nil {
			iCh <- result{err: err}
			return
		}
		iCh <- result{cs: [2]*cipherState{c1, c2}, hash: hs.ss.h}
	}()

	go func() {
		hs := newHandshakeStateFixed(respStatic, respEphemeral, prologue)
		if err := hs.readMsg0(rConn); err != nil {
			rCh <- result{err: err}
			return
		}
		if err := hs.writeMsg1(rConn, mustDecodeHex(t, vec.Messages[1].Payload)); err != nil {
			rCh <- result{err: err}
			return
		}
		c1, c2, err := hs.readMsg2(rConn)
		if err != nil {
			rCh <- result{err: err}
			return
		}
		rCh <- result{cs: [2]*cipherState{c1, c2}, hash: hs.ss.h}
	}()

	ir := <-iCh
	rr := <-rCh

	if ir.err != nil {
		t.Fatalf("initiator: %v", ir.err)
	}
	if rr.err != nil {
		t.Fatalf("responder: %v", rr.err)
	}

	wantHash := mustDecodeHex(t, vec.HandshakeHash)
	if !bytes.Equal(ir.hash[:], wantHash) {
		t.Errorf("initiator handshake_hash\n got  %x\n want %x", ir.hash, wantHash)
	}
	if !bytes.Equal(rr.hash[:], wantHash) {
		t.Errorf("responder handshake_hash\n got  %x\n want %x", rr.hash, wantHash)
	}

	// Post-handshake messages: initiator sends on c2, responder sends on c1.
	// msg[3]: initiator→responder, msg[4]: responder→initiator, msg[5]: initiator→responder
	postMessages := []struct {
		sender  *cipherState
		payload string
		ctext   string
	}{
		{ir.cs[1], vec.Messages[3].Payload, vec.Messages[3].Ciphertext},
		{rr.cs[0], vec.Messages[4].Payload, vec.Messages[4].Ciphertext},
		{ir.cs[1], vec.Messages[5].Payload, vec.Messages[5].Ciphertext},
	}

	for i, m := range postMessages {
		payload := mustDecodeHex(t, m.payload)
		wantCT := mustDecodeHex(t, m.ctext)
		gotCT := m.sender.encrypt([]byte{}, payload)
		if !bytes.Equal(gotCT, wantCT) {
			t.Errorf("message[%d] ciphertext\n got  %x\n want %x", i+3, gotCT, wantCT)
		}
	}
}
