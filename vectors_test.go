package noise

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
)

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

// The Noise_XX_25519_ChaChaPoly_BLAKE2s vector from the cacophony test suite.
// Source: https://github.com/mcginty/snow/blob/master/tests/vectors/cacophony.txt
const vectorJSON = `{
  "protocol_name": "Noise_XX_25519_ChaChaPoly_BLAKE2s",
  "init_prologue": "4a6f686e2047616c74",
  "init_static": "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
  "init_ephemeral": "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
  "resp_prologue": "4a6f686e2047616c74",
  "resp_static": "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
  "resp_ephemeral": "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
  "handshake_hash": "6c4c56cf71612f72d05ceb96c0155e6f4ea54a26b504c93de632a2db4a49d200",
  "messages": [
    {"payload": "4c756477696720766f6e204d69736573",
     "ciphertext": "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"},
    {"payload": "4d757272617920526f746862617264",
     "ciphertext": "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088437c365eb362a1c991b0557fe8a7fb187d99346765d93ec63db6c1b01504ebeec55a2298d2dbff80eff034d20595153f63a196a6cead1e11b2bb13e336fa13616dd3e8b0a070c882ed3f1a78c7c06c93"},
    {"payload": "462e20412e20486179656b",
     "ciphertext": "46c3307de83b014258717d97781c1f50936d8b7d50c0722a1739654d10392d415b670c114f79b9a4f80541570f77ce88802efa4220cff733e7b5668ba38059ec904b4b8eef9448085faf51"},
    {"payload": "4361726c204d656e676572",
     "ciphertext": "d5e83adfaac5dc324a68f1862df54549e56d209fba707205f328b2"},
    {"payload": "4a65616e2d426170746973746520536179",
     "ciphertext": "d102c9029b1f55c788f561ba7737afbccef9c9f1bf2f238167fd40ba9c1c134867"},
    {"payload": "457567656e2042f6686d20766f6e2042617765726b",
     "ciphertext": "cb1ce80960382c6d5d5e740ffb724d1432f0310b200fb6f8424120f506092744baa415e155"}
  ]
}`

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

	// Derive public key from private key.
	pub, err := derivePublicKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	kp.PublicKey = pub
	return kp
}

// TestSpecVectors verifies the implementation against the official
// Noise_XX_25519_ChaChaPoly_BLAKE2s test vector from the cacophony suite.
// This is the correctness baseline: passing these vectors proves spec-compliance,
// not just self-consistency.
func TestSpecVectors(t *testing.T) {
	var vec cacophonyVector
	if err := json.Unmarshal([]byte(vectorJSON), &vec); err != nil {
		t.Fatalf("parse vector: %v", err)
	}

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

	// Run initiator with fixed keys
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

	// Run responder with fixed keys
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

	// Verify handshake hash matches the vector.
	wantHash := mustDecodeHex(t, vec.HandshakeHash)
	if !bytes.Equal(ir.hash[:], wantHash) {
		t.Errorf("initiator handshake_hash\n got  %x\n want %x", ir.hash, wantHash)
	}
	if !bytes.Equal(rr.hash[:], wantHash) {
		t.Errorf("responder handshake_hash\n got  %x\n want %x", rr.hash, wantHash)
	}

	// Verify post-handshake message ciphertexts match the vector.
	// msg[3]: initiator sends (uses c2 = ir.cs[1]), responder receives
	// msg[4]: responder sends (uses c1 = rr.cs[0]), initiator receives
	// msg[5]: initiator sends (uses c2 = ir.cs[1], nonce 1), responder receives
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
