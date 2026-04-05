package XHDWalletAPI

import (
	"bytes"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// newTestWallet is a helper that returns a Peikert wallet from the shared test seed.
func newTestWallet(t *testing.T) *Wallet {
	t.Helper()
	w, err := NewWalletWithDerivation(mustHex(testSeedHex), Peikert)
	if err != nil {
		t.Fatalf("NewWalletWithDerivation: %v", err)
	}
	return w
}

// TestPath00 verifies that Path00 constructs the correct AlgoPath.
func TestPath00(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(5)
	if ap.account != 0 || ap.change != 0 || ap.keyIndex != 5 {
		t.Errorf("Path00(5): got account=%d change=%d keyIndex=%d, want 0/0/5",
			ap.account, ap.change, ap.keyIndex)
	}
	if ap.ctx != AlgoCoinType {
		t.Errorf("Path00: ctx = %v, want AlgoCoinType", ap.ctx)
	}
	if ap.w != w {
		t.Error("Path00: wallet pointer mismatch")
	}
}

// TestPath verifies that Path constructs the correct AlgoPath.
func TestPath(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path(2, 1, 7)
	if ap.account != 2 || ap.change != 1 || ap.keyIndex != 7 {
		t.Errorf("Path(2,1,7): got account=%d change=%d keyIndex=%d", ap.account, ap.change, ap.keyIndex)
	}
	if ap.ctx != AlgoCoinType {
		t.Errorf("Path: ctx = %v, want AlgoCoinType", ap.ctx)
	}
}

// TestAlgoPathAlgorandAddress verifies that AlgoPath.AlgorandAddress returns an
// address whose bytes match the direct KeyGen result.
func TestAlgoPathAlgorandAddress(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	addr, err := ap.AlgorandAddress()
	if err != nil {
		t.Fatalf("AlgorandAddress: %v", err)
	}

	pk, err := w.KeyGen(AlgoCoinType, 0, 0, 0)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	if !bytes.Equal(addr[:], pk) {
		t.Errorf("address bytes mismatch\n got:  %x\n want: %x", addr[:], pk)
	}
}

// TestAlgoPathAlgorandAddress_Various checks several account/change/index combos.
func TestAlgoPathAlgorandAddress_Various(t *testing.T) {
	w := newTestWallet(t)
	cases := []struct{ account, change, keyIndex uint32 }{
		{0, 0, 0},
		{0, 0, 1},
		{1, 0, 0},
		{2, 0, 1},
	}
	for _, c := range cases {
		ap := w.Path(c.account, c.change, c.keyIndex)
		addr, err := ap.AlgorandAddress()
		if err != nil {
			t.Errorf("AlgorandAddress(%d,%d,%d): %v", c.account, c.change, c.keyIndex, err)
			continue
		}
		pk, _ := w.KeyGen(AlgoCoinType, c.account, c.change, c.keyIndex)
		if !bytes.Equal(addr[:], pk) {
			t.Errorf("AlgorandAddress(%d,%d,%d) mismatch", c.account, c.change, c.keyIndex)
		}
	}
}

// TestAlgoPathSignData verifies that AlgoPath.SignData produces a valid signature.
func TestAlgoPathSignData(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	msg := []byte("hello algorand sdk")
	sig, err := ap.SignData(msg)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("sig length = %d, want 64", len(sig))
	}

	pk, _ := w.KeyGen(AlgoCoinType, 0, 0, 0)
	if !VerifyWithPublicKey(sig, msg, pk) {
		t.Fatal("signature did not verify")
	}
}

// TestAlgoPathSignData_RejectsTags verifies the tag-rejection is forwarded.
func TestAlgoPathSignData_RejectsTags(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	for _, tag := range []string{"TX", "MX", "Program", "ProgData"} {
		data := append([]byte(tag), 0xAB, 0xCD)
		_, err := ap.SignData(data)
		if err != ErrTransactionTag {
			t.Errorf("tag %q: expected ErrTransactionTag, got %v", tag, err)
		}
	}
}

// TestAlgoPathSignBytes verifies that AlgoPath.SignBytes signs without tag checks.
func TestAlgoPathSignBytes(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	// "TX" prefix is allowed in SignBytes
	msg := []byte("TXsome raw bytes")
	sig, err := ap.SignBytes(msg)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("sig length = %d, want 64", len(sig))
	}

	pk, _ := w.KeyGen(AlgoCoinType, 0, 0, 0)
	if !VerifyWithPublicKey(sig, msg, pk) {
		t.Fatal("SignBytes signature did not verify")
	}
}

// TestAlgoPathSignBytes_Verify verifies AlgoPath.SignBytes across multiple key indices.
func TestAlgoPathSignBytes_MultipleKeys(t *testing.T) {
	w := newTestWallet(t)
	msg := []byte("raw message")
	for idx := uint32(0); idx < 3; idx++ {
		ap := w.Path00(idx)
		sig, err := ap.SignBytes(msg)
		if err != nil {
			t.Fatalf("SignBytes(idx=%d): %v", idx, err)
		}
		pk, _ := w.KeyGen(AlgoCoinType, 0, 0, idx)
		if !VerifyWithPublicKey(sig, msg, pk) {
			t.Errorf("SignBytes(idx=%d): signature did not verify", idx)
		}
	}
}

// TestAlgoPathSignTransaction_SenderMatch tests signing when sender == derived address.
func TestAlgoPathSignTransaction_SenderMatch(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	addr, err := ap.AlgorandAddress()
	if err != nil {
		t.Fatalf("AlgorandAddress: %v", err)
	}

	tx := types.Transaction{
		Type: "pay",
		Header: types.Header{
			Sender:      addr,
			Fee:         1000,
			FirstValid:  1,
			LastValid:   1000,
			GenesisHash: [32]byte{1},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: addr,
			Amount:   types.MicroAlgos(100),
		},
	}

	txid, stxBytes, err := ap.SignTransaction(tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	if txid == "" {
		t.Fatal("txid is empty")
	}
	if len(stxBytes) == 0 {
		t.Fatal("stxBytes is empty")
	}

	// Decode and check AuthAddr is not set (sender == derived address).
	var stx types.SignedTxn
	err = msgpack.Decode(stxBytes, &stx)
	if err != nil {
		t.Fatalf("decode stxBytes: %v", err)
	}
	if stx.AuthAddr != (types.Address{}) {
		t.Errorf("AuthAddr should be zero when sender matches; got %v", stx.AuthAddr)
	}
	if stx.Txn.Sender != addr {
		t.Errorf("Sender mismatch after decode")
	}
}

// TestAlgoPathSignTransaction_SenderMismatch tests that AuthAddr is set when sender differs.
func TestAlgoPathSignTransaction_SenderMismatch(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	derivedAddr, err := ap.AlgorandAddress()
	if err != nil {
		t.Fatalf("AlgorandAddress: %v", err)
	}

	// Use a different address as sender (Peikert index 1 key — distinct from index 0)
	var otherAddr types.Address
	copy(otherAddr[:], mustHex("5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519"))

	tx := types.Transaction{
		Type: "pay",
		Header: types.Header{
			Sender:      otherAddr,
			Fee:         1000,
			FirstValid:  1,
			LastValid:   1000,
			GenesisHash: [32]byte{1},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: otherAddr,
			Amount:   types.MicroAlgos(1),
		},
	}

	txid, stxBytes, err := ap.SignTransaction(tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	if txid == "" {
		t.Fatal("txid is empty")
	}

	var stx types.SignedTxn
	if err := msgpack.Decode(stxBytes, &stx); err != nil {
		t.Fatalf("decode stxBytes: %v", err)
	}
	if stx.AuthAddr != derivedAddr {
		t.Errorf("AuthAddr = %v, want derived addr %v", stx.AuthAddr, derivedAddr)
	}
}

// TestAlgoPathSignTransaction_SignatureVerifies checks the signature inside the stx is valid.
func TestAlgoPathSignTransaction_SignatureVerifies(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	addr, _ := ap.AlgorandAddress()
	tx := types.Transaction{
		Type: "pay",
		Header: types.Header{
			Sender:      addr,
			Fee:         1000,
			FirstValid:  1,
			LastValid:   1000,
			GenesisHash: [32]byte{2},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: addr,
			Amount:   types.MicroAlgos(42),
		},
	}

	_, stxBytes, err := ap.SignTransaction(tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	var stx types.SignedTxn
	if err := msgpack.Decode(stxBytes, &stx); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Re-compute the bytes-to-sign and verify against the embedded signature.
	toBeSigned := rawTransactionBytesToSign(tx)
	pk, _ := w.KeyGen(AlgoCoinType, 0, 0, 0)
	if !VerifyWithPublicKey(stx.Sig[:], toBeSigned, pk) {
		t.Fatal("transaction signature did not verify")
	}
}

// TestAlgoPathSignTransaction_TxIDConsistency verifies the returned txid is deterministic.
func TestAlgoPathSignTransaction_TxIDConsistency(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	addr, _ := ap.AlgorandAddress()
	tx := types.Transaction{
		Type: "pay",
		Header: types.Header{
			Sender:      addr,
			Fee:         1000,
			FirstValid:  10,
			LastValid:   1010,
			GenesisHash: [32]byte{3},
		},
	}

	txid1, _, _ := ap.SignTransaction(tx)
	txid2, _, _ := ap.SignTransaction(tx)
	if txid1 != txid2 {
		t.Errorf("txid is not deterministic: %q != %q", txid1, txid2)
	}
	if txid1 == "" {
		t.Error("txid is empty")
	}
}

// TestAlgoPathSignTransaction_SpecificTxID verifies that a known transaction
// produces a fixed, expected txid (golden-value regression test).
func TestAlgoPathSignTransaction_SpecificTxID(t *testing.T) {
	w := newTestWallet(t)
	ap := w.Path00(0)

	addr, err := ap.AlgorandAddress()
	if err != nil {
		t.Fatalf("AlgorandAddress: %v", err)
	}

	// Fixed transaction with deterministic parameters.
	tx := types.Transaction{
		Type: "pay",
		Header: types.Header{
			Sender:      addr,
			Fee:         1000,
			FirstValid:  100,
			LastValid:   1100,
			GenesisHash: [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: addr,
			Amount:   types.MicroAlgos(500000),
		},
	}

	txid, _, err := ap.SignTransaction(tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	const wantTxID = "ECRJDPM2GYQQS6SA577AB6STPEFMNFCIEV6FTGN7BSDHZE23IEEA"
	if txid != wantTxID {
		t.Errorf("txid = %q, want %q", txid, wantTxID)
	}
}

// TestPath00VsPath ensures Path00(n) == Path(0,0,n).
func TestPath00VsPath(t *testing.T) {
	w := newTestWallet(t)
	for idx := uint32(0); idx < 3; idx++ {
		ap1 := w.Path00(idx)
		ap2 := w.Path(0, 0, idx)

		addr1, _ := ap1.AlgorandAddress()
		addr2, _ := ap2.AlgorandAddress()
		if addr1 != addr2 {
			t.Errorf("idx=%d: Path00 and Path(0,0,n) differ", idx)
		}
	}
}
