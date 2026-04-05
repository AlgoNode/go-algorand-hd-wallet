package XHDWalletAPI

import (
	"bytes"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
)

// Wallet provides the high-level HD wallet API for Algorand (ARC-0052).
type Wallet struct {
	rootKey        ExtendedKey
	derivationType DerivationType
}

// NewWalletWithDerivation creates an HD wallet with a specified derivation type.
func NewWalletWithDerivation(seed []byte, dt DerivationType) (*Wallet, error) {
	rootKey, err := FromSeed(seed)
	if err != nil {
		return nil, err
	}
	return &Wallet{rootKey: rootKey, derivationType: dt}, nil
}

// NewWallet creates an HD wallet from BIP-39 seed bytes (Peikert default).
func NewWallet(seed []byte) (*Wallet, error) {
	return NewWalletWithDerivation(seed, Peikert)
}

// BIP39Seed derives a 64-byte BIP-39 seed from a mnemonic and optional passphrase.
// Uses PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64).
func BIP39Seed(mnemonic, passphrase string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+passphrase), 2048, 64, sha512.New)
}

// NewWalletFromMnemonic creates an HD wallet from a BIP-39 mnemonic and optional passphrase.
func NewWalletFromMnemonic(mnemonic, passphrase string) (*Wallet, error) {
	return NewWallet(BIP39Seed(mnemonic, passphrase))
}

func hasAlgorandTag(data []byte) bool {
	// Prefixes from go-algorand protocol/hash.go (matching Kotlin reference)
	prefixes := []string{
		"appID", "arc", "aB", "aD", "aO", "aP", "aS", "AS",
		"BH", "B256", "BR", "CR", "GE", "KP", "MA", "MB", "MX",
		"NIC", "NIR", "NIV", "NPR", "OT1", "OT2", "PF", "PL",
		"Program", "ProgData", "PS", "PK", "SD", "SpecialAddr",
		"STIB", "spc", "spm", "spp", "sps", "spv", "TE", "TG", "TL", "TX", "VO",
	}
	for _, p := range prefixes {
		if bytes.HasPrefix(data, []byte(p)) {
			return true
		}
	}
	return false
}

// SignData signs arbitrary data, rejecting Algorand transaction tag prefixes.
func (w *Wallet) SignData(ctx KeyContext, account, change, keyIndex uint32, data []byte) ([]byte, error) {
	if hasAlgorandTag(data) {
		return nil, ErrTransactionTag
	}
	return w.signRaw(ctx, account, change, keyIndex, data)
}

// SignAlgoTransaction signs an Algorand transaction's bytes-to-sign (including "TX" prefix).
func (w *Wallet) SignAlgoTransaction(ctx KeyContext, account, change, keyIndex uint32, txBytes []byte) ([]byte, error) {
	return w.signRaw(ctx, account, change, keyIndex, txBytes)
}

// AlgorandAddress returns the Algorand address for the given derivation params.
func (w *Wallet) AlgorandAddress(account, change, keyIndex uint32) ([]byte, error) {
	pk, err := w.KeyGen(AlgoCoinType, account, change, keyIndex)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// RootKey returns a copy of the root extended private key.
func (w *Wallet) RootKey() ExtendedKey {
	k := make(ExtendedKey, len(w.rootKey))
	copy(k, w.rootKey)
	return k
}

func bip44Path(ctx KeyContext, account, change, keyIndex uint32) []uint32 {
	return []uint32{Harden(BIP44Purpose), Harden(uint32(ctx)), Harden(account), change, keyIndex}
}

// KeyGen derives the 32-byte Ed25519 public key at m'/44'/coinType'/account'/change/keyIndex.
func (w *Wallet) KeyGen(ctx KeyContext, account, change, keyIndex uint32) ([]byte, error) {
	path := bip44Path(ctx, account, change, keyIndex)
	ext, err := DeriveKey(w.rootKey, path, true, w.derivationType)
	if err != nil {
		return nil, err
	}
	return publicKeyFromPrivate(ext[0:32]), nil
}

// DeriveKeyExtended derives an extended key along a custom path.
func (w *Wallet) DeriveKeyExtended(path []uint32, isPrivate bool) (ExtendedKey, error) {
	return DeriveKey(w.rootKey, path, isPrivate, w.derivationType)
}

// signRaw signs a message with the key at the given BIP-44 path.
// Uses Ed25519 extended-key signing (BIP32-Ed25519 §V.C).
func (w *Wallet) signRaw(ctx KeyContext, account, change, keyIndex uint32, message []byte) ([]byte, error) {
	path := bip44Path(ctx, account, change, keyIndex)
	ext, err := DeriveKey(w.rootKey, path, true, w.derivationType)
	if err != nil {
		return nil, err
	}
	return signWithExtendedKey(ext, message)
}

func signWithExtendedKey(ext ExtendedKey, message []byte) ([]byte, error) {
	if len(ext) != 96 {
		return nil, ErrInvalidKeyLen
	}
	kL, kR := ext[0:32], ext[32:64]
	A := publicKeyFromPrivate(kL)

	// r = SHA-512(kR || message) mod l
	rH := sha512.New()
	rH.Write(kR)
	rH.Write(message)
	rScalar, _ := edwards25519.NewScalar().SetUniformBytes(rH.Sum(nil))

	// R = r * B
	R := edwards25519.NewGeneratorPoint().ScalarBaseMult(rScalar)

	// S = (r + SHA-512(R||A||message) * kL) mod l
	hH := sha512.New()
	hH.Write(R.Bytes())
	hH.Write(A)
	hH.Write(message)
	hScalar, _ := edwards25519.NewScalar().SetUniformBytes(hH.Sum(nil))
	kLScalar, _ := edwards25519.NewScalar().SetBytesWithClamping(kL)
	sScalar := edwards25519.NewScalar().Add(rScalar, edwards25519.NewScalar().Multiply(hScalar, kLScalar))

	sig := make([]byte, 64)
	copy(sig[0:32], R.Bytes())
	copy(sig[32:64], sScalar.Bytes())
	return sig, nil
}

// VerifyWithPublicKey verifies an Ed25519 signature.
func VerifyWithPublicKey(signature, message, publicKey []byte) bool {
	if len(signature) != 64 || len(publicKey) != 32 {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(signature[0:32])
	if err != nil {
		return false
	}
	S, err := edwards25519.NewScalar().SetCanonicalBytes(signature[32:64])
	if err != nil {
		return false
	}
	A, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return false
	}

	hH := sha512.New()
	hH.Write(R.Bytes())
	hH.Write(publicKey)
	hH.Write(message)
	kScalar, _ := edwards25519.NewScalar().SetUniformBytes(hH.Sum(nil))

	// Check: [S]*B == R + [k]*A
	sB := edwards25519.NewGeneratorPoint().ScalarBaseMult(S)
	kA := new(edwards25519.Point).ScalarMult(kScalar, A)
	rPlusKA := new(edwards25519.Point).Add(R, kA)
	return sB.Equal(rPlusKA) == 1
}

// Verify verifies a signature using this wallet's derived key.
func (w *Wallet) Verify(ctx KeyContext, account, change, keyIndex uint32, signature, message []byte) (bool, error) {
	pk, err := w.KeyGen(ctx, account, change, keyIndex)
	if err != nil {
		return false, err
	}
	return VerifyWithPublicKey(signature, message, pk), nil
}

// ECDH computes a shared secret via Elliptic Curve Diffie-Hellman.
// Ed25519 keys are converted to X25519 internally.
// Result = SHA-512(sharedPoint || pk1 || pk2) where order depends on meFirst.
func (w *Wallet) ECDH(ctx KeyContext, account, change, keyIndex uint32, otherPub []byte, meFirst bool) ([]byte, error) {
	path := bip44Path(ctx, account, change, keyIndex)
	ext, err := DeriveKey(w.rootKey, path, true, w.derivationType)
	if err != nil {
		return nil, err
	}
	kL := ext[0:32]
	myEdPub := publicKeyFromPrivate(kL)

	myX25519Priv := edPrivToX25519(kL)
	myX25519Pub, err := edPubToX25519(myEdPub)
	if err != nil {
		return nil, err
	}
	otherX25519Pub, err := edPubToX25519(otherPub)
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(myX25519Priv, otherX25519Pub)
	if err != nil {
		return nil, err
	}

	h := sha512.New()
	h.Write(shared)
	if meFirst {
		h.Write(myX25519Pub)
		h.Write(otherX25519Pub)
	} else {
		h.Write(otherX25519Pub)
		h.Write(myX25519Pub)
	}
	return h.Sum(nil), nil
}

// DeriveChildPublicFromExtended derives the Nth child public key from an extended public key.
func (w *Wallet) DeriveChildPublicFromExtended(xpk ExtendedKey, index uint32) ([]byte, error) {
	child, err := DeriveChildNodePublic(xpk, index, w.derivationType)
	if err != nil {
		return nil, err
	}
	return child[0:32], nil
}

// Export returns a copy of the root key.
func (w *Wallet) Export() ExtendedKey { return w.RootKey() }

// ImportRootKey creates a Wallet from a 96-byte root key.
func ImportRootKey(rootKey ExtendedKey, dt DerivationType) (*Wallet, error) {
	if len(rootKey) != 96 {
		return nil, ErrInvalidKeyLen
	}
	k := make(ExtendedKey, 96)
	copy(k, rootKey)
	return &Wallet{rootKey: k, derivationType: dt}, nil
}

// Wipe zeros the root key material.
func (w *Wallet) Wipe() {
	for i := range w.rootKey {
		w.rootKey[i] = 0
	}
}

// SignBytes signs raw bytes without tag checks.
func (w *Wallet) SignBytes(ctx KeyContext, account, change, keyIndex uint32, data []byte) ([]byte, error) {
	return w.signRaw(ctx, account, change, keyIndex, data)
}

// --- X25519 helpers ---

func edPrivToX25519(kL []byte) []byte {
	x := make([]byte, 32)
	copy(x, kL)
	return x
}

func edPubToX25519(edPub []byte) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}
