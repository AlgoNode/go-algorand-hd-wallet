# Algorand HD Wallet — Go

A Go implementation of **ARC-0052** (BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace) for Algorand, based on the [Kotlin reference implementation](https://github.com/algorandfoundation/xHD-Wallet-API-kt).

> **Note:** This library has not undergone audit and is not recommended for production use.

## Features

- **BIP32-Ed25519 key derivation** with full BIP-44 path support (`m'/44'/coinType'/account'/change/keyIndex`)
- **Two derivation modes:**
  - **Khovratovich** (standard, g=32) — compatible with reference implementations
  - **Peikert** (g=9) — more secure amendment, default in the Kotlin/TS/Swift libraries
- **Ed25519 extended-key signing** — modified EdDSA per the BIP32-Ed25519 paper
- **Signature verification** — standard Ed25519 verification
- **ECDH** — Diffie-Hellman via Ed25519→X25519 conversion
- **Public child key derivation** — derive N child public keys from a single extended public key
- **Algorand address generation** — via `go-algorand-sdk` `types.Address`
- **Tag-safe signing** — `SignData` rejects Algorand transaction tag prefixes; use `SignAlgoTransaction` for transactions
- **Validated** against the TypeScript reference implementation ([algorandfoundation/xHD-Wallet-API-ts](https://github.com/algorandfoundation/xHD-Wallet-API-ts)) using Peikert test vectors

## Dependencies

| Module | Purpose |
|--------|---------|
| `filippo.io/edwards25519` | Ed25519 point/scalar arithmetic |
| `github.com/algorand/go-algorand-sdk/v2` | `types.Address` for Algorand addresses |
| `golang.org/x/crypto` | PBKDF2 for BIP-39 seed generation |

## Installation

```
go get github.com/algonode/go-algorand-hd-wallet/XHDWalletAPI
```

## Usage

### Create a wallet from a BIP-39 seed

```go
import (
    "crypto/sha512"
    "github.com/algonode/go-algorand-hd-wallet/XHDWalletAPI"
    "golang.org/x/crypto/pbkdf2"
)

// BIP-39 seed from mnemonic
mnemonic := "salon zoo engage submit smile frost ..."
seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)

// Create wallet (Peikert derivation by default)
wallet, err := XHDWalletAPI.NewWallet(seed)

// Or with explicit Khovratovich derivation
wallet, err := XHDWalletAPI.NewWalletWithDerivation(seed, XHDWalletAPI.Khovratovich)
```

### Generate a public key

```go
// m'/44'/283'/0'/0/0
pk, err := wallet.KeyGen(XHDWalletAPI.Address, 0, 0, 0)
```

### Get an Algorand address

```go
addr, err := wallet.AlgorandAddress(0, 0, 0)
fmt.Println(addr.String()) // e.g. ML7IGK322ECUJPUDG6THAQ26KBSK4STG4555PCI...
```

### Sign and verify

```go
// Sign arbitrary data (rejects Algorand transaction tags)
sig, err := wallet.SignData(XHDWalletAPI.Address, 0, 0, 0, []byte("hello"))

// Sign an Algorand transaction
sig, err := wallet.SignAlgoTransaction(XHDWalletAPI.Address, 0, 0, 0, tx.BytesToSign())

// Verify
ok := XHDWalletAPI.VerifyWithPublicKey(sig, message, pk)
```

### ECDH shared secret

```go
// Alice and Bob agree on ordering (meFirst)
secret, err := alice.ECDH(XHDWalletAPI.Address, 0, 0, 0, bobPK, true)
secret, err := bob.ECDH(XHDWalletAPI.Address, 0, 0, 0, alicePK, false)
// secret values are identical
```

### Public child key derivation

Derive N child keys from a single extended public key without the private key:

```go
// Get extended public key at change level: m'/44'/283'/0'/0
xpk, err := wallet.DeriveKeyExtended(
    []uint32{XHDWalletAPI.Harden(44), XHDWalletAPI.Harden(283), XHDWalletAPI.Harden(0), 0},
    false, // public
)

// Derive child public keys at keyIndex 0, 1, 2, ...
childPK, err := wallet.DeriveChildPublicFromExtended(xpk, 0)
```

### End-to-end example: addresses + sign a transaction

```go
package main

import (
    "fmt"
    "log"

    "github.com/algorand/go-algorand-sdk/v2/types"
    wallet "github.com/algonode/go-algorand-hd-wallet/XHDWalletAPI"
)

func main() {
    mnemonic := "salon zoo engage submit smile frost later decide wing sight chaos renew" +
        " lizard rely canal coral scene hobby scare step bus leaf tobacco slice"

    w, err := wallet.NewWalletFromMnemonic(mnemonic, "")
    if err != nil {
        log.Fatal(err)
    }
    defer w.Wipe()

    // Print first 10 addresses (m'/44'/283'/0'/0/0 … /9)
    fmt.Println("First 10 Algorand addresses:")
    for i := uint32(0); i < 10; i++ {
        addr, err := w.Path00(i).AlgorandAddress()
        if err != nil {
            log.Fatal(err)
        }
        fmt.Printf("  [%d] %s\n", i, addr)
    }

    // Build a dummy 0-ALGO pay transaction signed by address index 1
    signer := w.Path00(1)
    sender, err := signer.AlgorandAddress()
    if err != nil {
        log.Fatal(err)
    }
    receiver, err := w.Path00(0).AlgorandAddress()
    if err != nil {
        log.Fatal(err)
    }

    tx := types.Transaction{
        Type: types.PaymentTx,
        Header: types.Header{
            Sender:      sender,
            Fee:         types.MicroAlgos(1000),
            FirstValid:  types.Round(1),
            LastValid:   types.Round(1000),
            GenesisHash: [32]byte{}, // zeroed — replace with real genesis hash
        },
        PaymentTxnFields: types.PaymentTxnFields{
            Receiver: receiver,
            Amount:   types.MicroAlgos(0),
        },
    }

    txid, stxBytes, err := signer.SignTransaction(tx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("\nSigned by: %s\n", sender)
    fmt.Printf("TxID:      %s\n", txid)
    fmt.Printf("stxBytes:  %d bytes\n", len(stxBytes))
}
```

### Cleanup

```go
wallet.Wipe() // zeros root key material
```

## Derivation Types

| Type | g | Bits randomized | Safe levels | Notes |
|------|---|-----------------|-------------|-------|
| Khovratovich | 32 | 224 | 2²⁶ | Standard BIP32-Ed25519 paper |
| Peikert | 9 | 247 | 8 | More secure; sufficient for BIP-44's 5 levels |

## Architecture

```
XHDWalletAPI/
├── types.go        — KeyContext, DerivationType, errors, Harden()
├── derive.go       — FromSeed, DeriveKey, DeriveChildNodePublic, truncGBits, scalarFromLEBytes
├── wallet.go       — Wallet API: KeyGen, SignData, SignAlgoTransaction, ECDH, AlgorandAddress
└── wallet_test.go  — tests validated against the TS reference implementation
```

## Test Vectors

Vectors taken from the [TypeScript reference implementation](https://github.com/algorandfoundation/xHD-Wallet-API-ts/blob/main/src/x.hd.wallet.api.crypto.spec.ts).

**Mnemonic:** `salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice`

**Root key (hex):**
```
a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f46
94592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05
796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946
```

### Peikert (g=9, default)

#### Address context (`m'/44'/283'/account'/0/keyIndex`)

| Path | Public Key (hex) |
|------|-----------------|
| m'/44'/283'/0'/0/0 | `7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9` |
| m'/44'/283'/0'/0/1 | `5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519` |
| m'/44'/283'/0'/0/2 | `00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3` |
| m'/44'/283'/1'/0/0 | `358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9` |
| m'/44'/283'/2'/0/1 | `1f0f75fbbca12b22523973191061b2f96522740e139a3420c730717ac5b0dfc0` |
| m'/44'/283'/3'/0/0 | `f035316f915b342ea5fe78dccb59d907b93805732219d436a1bd8488ff4e5b1b` |

#### Identity context (`m'/44'/0'/account'/0/keyIndex`)

| Path | Public Key (hex) |
|------|-----------------|
| m'/44'/0'/0'/0/0 | `ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a` |
| m'/44'/0'/0'/0/1 | `2b46c2af0890493e486049d456509a0199e565b41a5fb622f0ea4b9337bd2b97` |
| m'/44'/0'/0'/0/2 | `2713f135f19ef3dcfca73cb536b1e077b1165cd0b7bedbef709447319ff0016d` |
| m'/44'/0'/1'/0/0 | `232847ae1bb95babcaa50c8033fab98f59e4b4ad1d89ac523a90c830e4ceee4a` |
| m'/44'/0'/2'/0/1 | `8f68b6572860d84e8a41e38db1c8c692ded5eb291846f2e5bbfde774a9c6d16e` |

