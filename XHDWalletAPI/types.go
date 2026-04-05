// Package XHDWalletAPI implements BIP32-Ed25519 Hierarchical Deterministic Keys
// over a Non-linear Keyspace for Algorand's ARC-52.
//
// Reference: https://github.com/algorandfoundation/xHD-Wallet-API-kt
package XHDWalletAPI

import "errors"

// KeyContext represents the BIP-44 coin type for key derivation.
type KeyContext uint32

const (
	AlgoCoinType KeyContext = 283 // Algorand address coin type (283')
	Identity     KeyContext = 0   // Identity/W3C coin type (0')
)

// DerivationType selects the child key derivation algorithm variant.
type DerivationType int

const (
	// Peikert zeros top 9 bits of zL. More secure, max 8 safe derivation levels.
	Peikert DerivationType = iota
	// Khovratovich zeros top 32 bits of zL. Standard BIP32-Ed25519 paper.
	Khovratovich
)

const (
	BIP44Purpose   = 44
	HardenedOffset = 0x80000000
)

var (
	ErrInvalidSeed      = errors.New("XHDWalletAPI: seed produces invalid root key")
	ErrHardenedPublic   = errors.New("XHDWalletAPI: cannot derive hardened child from public key")
	ErrInvalidKeyLen    = errors.New("XHDWalletAPI: invalid key length")
	ErrTransactionTag   = errors.New("XHDWalletAPI: data contains Algorand transaction tag prefix")
	ErrInvalidPublicKey = errors.New("XHDWalletAPI: invalid public key")
	ErrOverflow         = errors.New("XHDWalletAPI: child key overflows 2^255")
	ErrInvalidSignature = errors.New("XHDWalletAPI: ed25519 library returned an invalid signature")
)

// Harden returns the hardened version of an index.
func Harden(index uint32) uint32 { return index + HardenedOffset }

// IsHardened returns true if the index is hardened.
func IsHardened(index uint32) bool { return index >= HardenedOffset }
