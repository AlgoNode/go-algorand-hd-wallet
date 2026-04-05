package XHDWalletAPI

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"slices"

	"filippo.io/edwards25519"
)

// ExtendedKey holds an extended private key [kL(32) || kR(32) || c(32)] = 96 bytes,
// or an extended public key [A(32) || c(32)] = 64 bytes.
type ExtendedKey []byte

// FromSeed derives the root extended private key from a BIP-39 seed (typically 64 bytes).
//
// Algorithm (BIP32-Ed25519 §V.A):
//  1. k = SHA-512(seed); split into kL, kR
//  2. While bit 253 of kL is set, retry: k = HMAC-SHA512(key=kL, data=kR)
//  3. Clamp kL: clear bits 0-2; clear bit 255; set bit 254
//  4. Chain code c = SHA-256(0x01 || seed)
//  5. Return kL || kR || c (96 bytes)
func FromSeed(seed []byte) (ExtendedKey, error) {
	k := sha512.Sum512(seed)
	kL := make([]byte, 32)
	kR := make([]byte, 32)
	copy(kL, k[:32])
	copy(kR, k[32:])

	for kL[31]&0x20 != 0 {
		mac := hmac.New(sha512.New, kL)
		mac.Write(kR)
		k2 := mac.Sum(nil)
		copy(kL, k2[:32])
		copy(kR, k2[32:])
	}

	kL[0] &= 0xF8
	kL[31] &= 0x7F
	kL[31] |= 0x40

	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(seed)
	c := h.Sum(nil)

	root := make(ExtendedKey, 96)
	copy(root[0:32], kL)
	copy(root[32:64], kR)
	copy(root[64:96], c)
	return root, nil
}

// truncGBits zeroes the top g bits of a 32-byte LE value.
func truncGBits(src []byte, g int) []byte {
	out := make([]byte, 32)
	copy(out, src)
	rem := g
	for i := 31; i >= 0 && rem > 0; i-- {
		if rem >= 8 {
			out[i] = 0
			rem -= 8
		} else {
			out[i] &= byte(0xFF >> uint(rem))
			rem = 0
		}
	}
	return out
}

// gBits returns the truncation parameter g for the given derivation type.
func gBits(dt DerivationType) int {
	if dt == Khovratovich {
		return 32
	}
	return 9 // Peikert
}

// deriveChildNodePrivate derives a child extended private key.
func deriveChildNodePrivate(parent ExtendedKey, index uint32, dt DerivationType) (ExtendedKey, error) {
	if len(parent) != 96 {
		return nil, ErrInvalidKeyLen
	}
	kL, kR, c := parent[0:32], parent[32:64], parent[64:96]

	idxBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(idxBuf, index)

	var zData, cData []byte
	if IsHardened(index) {
		zData = slices.Concat([]byte{0x00}, kL, kR, idxBuf)
		cData = slices.Concat([]byte{0x01}, kL, kR, idxBuf)
	} else {
		A := publicKeyFromPrivate(kL)
		zData = slices.Concat([]byte{0x02}, A, idxBuf)
		cData = slices.Concat([]byte{0x03}, A, idxBuf)
	}

	Z := hmacSHA512sum(c, zData)
	chainHMAC := hmacSHA512sum(c, cData)

	zL := truncGBits(Z[0:32], gBits(dt))
	zR := Z[32:64]

	// kL_child = kL + 8 * trunc(zL)
	kLBig := new(big.Int).SetBytes(rev(kL))
	zLBig := new(big.Int).SetBytes(rev(zL))
	zLBig.Mul(zLBig, big.NewInt(8))
	kLChild := new(big.Int).Add(kLBig, zLBig)

	if kLChild.BitLen() > 254 {
		// Kotlin throws BigIntegerOverflowException for >= 2^255
		if kLChild.Cmp(new(big.Int).Lsh(big.NewInt(1), 255)) >= 0 {
			return nil, ErrOverflow
		}
	}

	// kR_child = (kR + zR) mod 2^256
	kRBig := new(big.Int).SetBytes(rev(kR))
	zRBig := new(big.Int).SetBytes(rev(zR))
	mod256 := new(big.Int).Lsh(big.NewInt(1), 256)
	kRChild := new(big.Int).Add(kRBig, zRBig)
	kRChild.Mod(kRChild, mod256)

	child := make(ExtendedKey, 96)
	copy(child[0:32], toLE32(kLChild))
	copy(child[32:64], toLE32(kRChild))
	copy(child[64:96], chainHMAC[32:64])
	return child, nil
}

// DeriveChildNodePublic derives a child extended public key (soft derivation only).
func DeriveChildNodePublic(parent ExtendedKey, index uint32, dt DerivationType) (ExtendedKey, error) {
	if len(parent) != 64 {
		return nil, ErrInvalidKeyLen
	}
	if IsHardened(index) {
		return nil, ErrHardenedPublic
	}

	A, c := parent[0:32], parent[32:64]
	idxBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(idxBuf, index)

	Z := hmacSHA512sum(c, slices.Concat([]byte{0x02}, A, idxBuf))
	chainHMAC := hmacSHA512sum(c, slices.Concat([]byte{0x03}, A, idxBuf))

	zL := truncGBits(Z[0:32], gBits(dt))
	zLBig := new(big.Int).SetBytes(rev(zL))
	zLBig.Mul(zLBig, big.NewInt(8))

	scalar := scalarFromBytes(toLE32(zLBig))
	zPoint := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalar)

	parentPoint, err := new(edwards25519.Point).SetBytes(A)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	childPoint := new(edwards25519.Point).Add(parentPoint, zPoint)

	child := make(ExtendedKey, 64)
	copy(child[0:32], childPoint.Bytes())
	copy(child[32:64], chainHMAC[32:64])
	return child, nil
}

// DeriveKey derives an extended key along a BIP-44 path.
// If isPrivate, returns 96-byte extended private key; else 64-byte extended public key.
func DeriveKey(rootKey ExtendedKey, path []uint32, isPrivate bool, dt DerivationType) (ExtendedKey, error) {
	if len(rootKey) != 96 {
		return nil, ErrInvalidKeyLen
	}
	cur := make(ExtendedKey, 96)
	copy(cur, rootKey)
	for _, idx := range path {
		child, err := deriveChildNodePrivate(cur, idx, dt)
		if err != nil {
			return nil, err
		}
		cur = child
	}
	if isPrivate {
		return cur, nil
	}
	A := publicKeyFromPrivate(cur[0:32])
	xpk := make(ExtendedKey, 64)
	copy(xpk[0:32], A)
	copy(xpk[32:64], cur[64:96])
	return xpk, nil
}

// publicKeyFromPrivate computes A = kL * B (Ed25519 base-point multiplication).
func publicKeyFromPrivate(kL []byte) []byte {
	s := scalarFromBytes(kL)
	return edwards25519.NewGeneratorPoint().ScalarBaseMult(s).Bytes()
}

// scalarFromBytes reduces the LE bytes mod l if needed.
func scalarFromBytes(b []byte) *edwards25519.Scalar {
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		n := new(big.Int).SetBytes(rev(b))
		l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		n.Mod(n, l)
		s, _ = edwards25519.NewScalar().SetCanonicalBytes(toLE32(n))
	}
	return s
}

// --- helpers ---

func hmacSHA512sum(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func rev(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return r
}

func toLE32(n *big.Int) []byte {
	be := n.Bytes()
	r := make([]byte, 32)
	for i, b := range be {
		idx := len(be) - 1 - i
		if idx < 32 {
			r[idx] = b
		}
	}
	return r
}

