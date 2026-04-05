package XHDWalletAPI

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// BIP39 seed from mnemonic "salon zoo engage submit smile frost later decide
// wing sight chaos renew lizard rely canal coral scene hobby scare step bus
// leaf tobacco slice" with empty passphrase.
const testSeedHex = "3aff2db416b895ec3cf9a4f8d1e970bc9819920e7bf44a5e350477af0ef557b1" +
	"511b0986debf78dd38c7c520cd44ff7c7231618f958e21ef0250733a8c1915ea"

const expectedRootKeyHex = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f46" +
	"94592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05" +
	"796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946"

// Expected private key for m'/44'/283'/0'/0/0 with Khovratovich derivation.
// From the Kotlin reference test suite (XHDWalletAPITest.kt).
const expectedPrivKeyKhov = "80102bb98faac3fd1789c2c6c559d3715cd9cac228d6d4b0f76a2346eaec8f46" +
	"01ae14284089243e936be91b2823cc142f753135eaff1bae20d3eec77870c544" +
	"9f92c790d7abaee0e00a4ec1fb78a1d438e8ccf7c2bad9a018a5bf9a5d510075"

// Public key test vectors from the Kotlin reference test suite.
// All use Khovratovich derivation.
var khovPubKeyTests = []struct {
	name    string
	ctx     KeyContext
	account uint32
	change  uint32
	keyIdx  uint32
	pubHex  string
}{
	{"m'/44'/283'/0'/0/0", AlgoCoinType, 0, 0, 0, "62fe832b7ad10544be8337a670435e5064ae4a66e77bd78909765b46b576a6f3"},
	{"m'/44'/283'/0'/0/1", AlgoCoinType, 0, 0, 1, "530461002eaccec0c7b5795925aa104a7fb45f85ef0aa95bbb5be93b6f8537ad"},
	{"m'/44'/283'/0'/0/2", AlgoCoinType, 0, 0, 2, "2281c81bee04ee039fa482c283541c6ab06c8324db6f1cc59c68252e1d58bcb3"},
	{"m'/44'/283'/1'/0/0", AlgoCoinType, 1, 0, 0, "9e12643f6c0068dcf53b04daced6f8c1a90ad21c954a66df4140d79303166a67"},
	{"m'/44'/283'/1'/0/1", AlgoCoinType, 1, 0, 1, "19fefaa427c8a6fb4cf80bb848e9c0c37aa2bf4cb19cf5ac9515ba1e6d988cba"},
	{"m'/44'/283'/2'/0/1", AlgoCoinType, 2, 0, 1, "8a5ddf62d51a2c50e51dbad4634356cc72314a81edd917ac91da96477a9fb5b0"},
	{"m'/44'/283'/3'/0/0", AlgoCoinType, 3, 0, 0, "2358e0f2b465ab3e8f55139d8316654d4be39ebb22367d36409fd02a20b0e017"},
	// Identity context (coin type 0')
	{"m'/44'/0'/0'/0/0", Identity, 0, 0, 0, "b6d7eea5af0ad83edf4340659e72f0ea2b4566de1fc3b63a40a425aabebe5e49"},
	{"m'/44'/0'/0'/0/1", Identity, 0, 0, 1, "b5cec676c5a2129ed1be4223a2702439bbb2462fd77b43f27e2f79fd194a30a2"},
	{"m'/44'/0'/0'/0/2", Identity, 0, 0, 2, "435e5e3446431d462572abee1b8badb88608906a6af27b8497bccfd503edb6fe"},
	{"m'/44'/0'/1'/0/0", Identity, 1, 0, 0, "bf63be83fff9bc9d0aebc231d50342110e5220247e50de376b47e154b5d32a3e"},
	{"m'/44'/0'/1'/0/2", Identity, 1, 0, 2, "46958e76db15157f401227f8acbdb709245dca0555c8e85f56b0d2052e834d06"},
	{"m'/44'/0'/2'/0/1", Identity, 2, 0, 1, "edb10fff24a4745df52f1a0ab1ae71b3752d019c8c2437d46ab8c8e634a74cd4"},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex: " + err.Error())
	}
	return b
}

func TestFromSeed(t *testing.T) {
	seed := mustHex(testSeedHex)
	rootKey, err := FromSeed(seed)
	if err != nil {
		t.Fatalf("FromSeed: %v", err)
	}
	want := mustHex(expectedRootKeyHex)
	if !bytes.Equal(rootKey, want) {
		t.Errorf("root key mismatch\n got:  %x\n want: %x", rootKey, want)
	}
}

func TestDerivePrivateKey_Khovratovich(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, err := NewWalletWithDerivation(seed, Khovratovich)
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}

	path := bip44Path(AlgoCoinType, 0, 0, 0)
	extKey, err := DeriveKey(w.rootKey, path, true, Khovratovich)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	want := mustHex(expectedPrivKeyKhov)
	if !bytes.Equal(extKey, want) {
		t.Errorf("private key mismatch\n got:  %x\n want: %x", extKey, want)
	}
}

func TestKeyGen_Khovratovich(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, err := NewWalletWithDerivation(seed, Khovratovich)
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}

	for _, tt := range khovPubKeyTests {
		t.Run(tt.name, func(t *testing.T) {
			pk, err := w.KeyGen(tt.ctx, tt.account, tt.change, tt.keyIdx)
			if err != nil {
				t.Fatalf("KeyGen: %v", err)
			}
			want := mustHex(tt.pubHex)
			if !bytes.Equal(pk, want) {
				t.Errorf("public key mismatch\n got:  %x\n want: %x", pk, want)
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, _ := NewWalletWithDerivation(seed, Khovratovich)

	msg := []byte("Hello, Algorand HD wallet!")
	sig, err := w.SignData(AlgoCoinType, 0, 0, 0, msg)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("sig length = %d, want 64", len(sig))
	}

	pk, _ := w.KeyGen(AlgoCoinType, 0, 0, 0)
	if !VerifyWithPublicKey(sig, msg, pk) {
		t.Fatal("valid signature did not verify")
	}
	if VerifyWithPublicKey(sig, []byte("tampered"), pk) {
		t.Fatal("tampered message should not verify")
	}
}

func TestSignDataRejectsTags(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, _ := NewWalletWithDerivation(seed, Khovratovich)

	for _, tag := range []string{"TX", "MX", "Program", "ProgData"} {
		data := append([]byte(tag), 0x01, 0x02)
		_, err := w.SignData(AlgoCoinType, 0, 0, 0, data)
		if err != ErrTransactionTag {
			t.Errorf("expected ErrTransactionTag for prefix %q, got %v", tag, err)
		}
	}
}

func TestPublicChildDerivation_Khovratovich(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, _ := NewWalletWithDerivation(seed, Khovratovich)

	// Extended public key at m'/44'/283'/0'/0
	xpk, err := w.DeriveKeyExtended(
		[]uint32{Harden(44), Harden(283), Harden(0), 0}, false)
	if err != nil {
		t.Fatalf("DeriveKeyExtended: %v", err)
	}

	for idx := uint32(0); idx <= 2; idx++ {
		childPK, err := w.DeriveChildPublicFromExtended(xpk, idx)
		if err != nil {
			t.Fatalf("DeriveChildPublic(%d): %v", idx, err)
		}
		directPK, _ := w.KeyGen(AlgoCoinType, 0, 0, idx)
		if !bytes.Equal(childPK, directPK) {
			t.Errorf("index %d: public child != direct\n child:  %x\n direct: %x", idx, childPK, directPK)
		}
	}
}

func TestPublicChildDerivation_Peikert(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, _ := NewWalletWithDerivation(seed, Peikert)

	xpk, err := w.DeriveKeyExtended(
		[]uint32{Harden(44), Harden(283), Harden(0), 0}, false)
	if err != nil {
		t.Fatalf("DeriveKeyExtended: %v", err)
	}

	for idx := uint32(0); idx <= 2; idx++ {
		childPK, err := w.DeriveChildPublicFromExtended(xpk, idx)
		if err != nil {
			t.Fatalf("DeriveChildPublic(%d): %v", idx, err)
		}
		directPK, _ := w.KeyGen(AlgoCoinType, 0, 0, idx)
		if !bytes.Equal(childPK, directPK) {
			t.Errorf("index %d: public child != direct\n child:  %x\n direct: %x", idx, childPK, directPK)
		}
	}
}

func TestHardenedPublicFails(t *testing.T) {
	xpk := make(ExtendedKey, 64) // dummy
	_, err := DeriveChildNodePublic(xpk, Harden(0), Peikert)
	if err != ErrHardenedPublic {
		t.Errorf("expected ErrHardenedPublic, got %v", err)
	}
}

func TestECDH(t *testing.T) {
	seed1 := mustHex(testSeedHex)
	w1, _ := NewWalletWithDerivation(seed1, Khovratovich)

	seed2 := make([]byte, len(seed1))
	copy(seed2, seed1)
	for i := 10; i < 20; i++ {
		seed2[i] ^= 0xAA
	}
	w2, err := NewWalletWithDerivation(seed2, Khovratovich)
	if err != nil {
		t.Skipf("second seed invalid: %v", err)
	}

	pk1, _ := w1.KeyGen(AlgoCoinType, 0, 0, 0)
	pk2, _ := w2.KeyGen(AlgoCoinType, 0, 0, 0)

	s1, err := w1.ECDH(AlgoCoinType, 0, 0, 0, pk2, true)
	if err != nil {
		t.Fatalf("ECDH(1→2): %v", err)
	}
	s2, err := w2.ECDH(AlgoCoinType, 0, 0, 0, pk1, false)
	if err != nil {
		t.Fatalf("ECDH(2→1): %v", err)
	}
	if !bytes.Equal(s1, s2) {
		t.Errorf("shared secrets differ\n s1: %x\n s2: %x", s1, s2)
	}
}

func TestDistinctKeys(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, _ := NewWalletWithDerivation(seed, Khovratovich)

	seen := map[string]bool{}
	for acct := uint32(0); acct < 5; acct++ {
		pk, _ := w.KeyGen(AlgoCoinType, acct, 0, 0)
		h := hex.EncodeToString(pk)
		if seen[h] {
			t.Errorf("duplicate key for account %d", acct)
		}
		seen[h] = true
	}
}

// Peikert public key test vectors from the TS reference implementation
// (algorandfoundation/xHD-Wallet-API-ts x.hd.wallet.api.crypto.spec.ts).
// These are the default derivation mode (g=9) vectors.
var peikertPubKeyTests = []struct {
	name    string
	ctx     KeyContext
	account uint32
	change  uint32
	keyIdx  uint32
	pubHex  string
}{
	// Address context (coin type 283)
	{"m'/44'/283'/0'/0/0", AlgoCoinType, 0, 0, 0, "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9"},
	{"m'/44'/283'/0'/0/1", AlgoCoinType, 0, 0, 1, "5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519"},
	{"m'/44'/283'/0'/0/2", AlgoCoinType, 0, 0, 2, "00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3"},
	{"m'/44'/283'/1'/0/0", AlgoCoinType, 1, 0, 0, "358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9"},
	{"m'/44'/283'/2'/0/1", AlgoCoinType, 2, 0, 1, "1f0f75fbbca12b22523973191061b2f96522740e139a3420c730717ac5b0dfc0"},
	{"m'/44'/283'/3'/0/0", AlgoCoinType, 3, 0, 0, "f035316f915b342ea5fe78dccb59d907b93805732219d436a1bd8488ff4e5b1b"},
	// Identity context (coin type 0)
	{"m'/44'/0'/0'/0/0", Identity, 0, 0, 0, "ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a"},
	{"m'/44'/0'/0'/0/1", Identity, 0, 0, 1, "2b46c2af0890493e486049d456509a0199e565b41a5fb622f0ea4b9337bd2b97"},
	{"m'/44'/0'/0'/0/2", Identity, 0, 0, 2, "2713f135f19ef3dcfca73cb536b1e077b1165cd0b7bedbef709447319ff0016d"},
	{"m'/44'/0'/1'/0/0", Identity, 1, 0, 0, "232847ae1bb95babcaa50c8033fab98f59e4b4ad1d89ac523a90c830e4ceee4a"},
	{"m'/44'/0'/2'/0/1", Identity, 2, 0, 1, "8f68b6572860d84e8a41e38db1c8c692ded5eb291846f2e5bbfde774a9c6d16e"},
}

func TestKeyGen_Peikert(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, err := NewWalletWithDerivation(seed, Peikert)
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}

	for _, tt := range peikertPubKeyTests {
		t.Run(tt.name, func(t *testing.T) {
			pk, err := w.KeyGen(tt.ctx, tt.account, tt.change, tt.keyIdx)
			if err != nil {
				t.Fatalf("KeyGen: %v", err)
			}
			want := mustHex(tt.pubHex)
			if !bytes.Equal(pk, want) {
				t.Errorf("public key mismatch\n got:  %x\n want: %x", pk, want)
			}
		})
	}
}

func TestPeikertDiffersFromKhovratovich(t *testing.T) {
	seed := mustHex(testSeedHex)
	wP, _ := NewWalletWithDerivation(seed, Peikert)
	wK, _ := NewWalletWithDerivation(seed, Khovratovich)

	pkP, _ := wP.KeyGen(AlgoCoinType, 0, 0, 0)
	pkK, _ := wK.KeyGen(AlgoCoinType, 0, 0, 0)

	if bytes.Equal(pkP, pkK) {
		t.Error("Peikert and Khovratovich should produce different keys")
	}
}

func TestImportExport(t *testing.T) {
	seed := mustHex(testSeedHex)
	w1, _ := NewWalletWithDerivation(seed, Khovratovich)

	w2, err := ImportRootKey(w1.Export(), Khovratovich)
	if err != nil {
		t.Fatalf("ImportRootKey: %v", err)
	}

	pk1, _ := w1.KeyGen(AlgoCoinType, 0, 0, 0)
	pk2, _ := w2.KeyGen(AlgoCoinType, 0, 0, 0)
	if !bytes.Equal(pk1, pk2) {
		t.Error("imported wallet produces different key")
	}
}

func TestWipe(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, _ := NewWalletWithDerivation(seed, Khovratovich)
	w.Wipe()
	for _, b := range w.rootKey {
		if b != 0 {
			t.Fatal("root key not fully wiped")
		}
	}
}

func TestAlgorandAddress(t *testing.T) {
	seed := mustHex(testSeedHex)
	w, _ := NewWalletWithDerivation(seed, Khovratovich)

	addr, err := w.AlgorandAddress(0, 0, 0)
	if err != nil {
		t.Fatalf("AlgorandAddress: %v", err)
	}

	pk, _ := w.KeyGen(AlgoCoinType, 0, 0, 0)
	if !bytes.Equal(addr[:], pk) {
		t.Error("address bytes don't match public key")
	}

}
