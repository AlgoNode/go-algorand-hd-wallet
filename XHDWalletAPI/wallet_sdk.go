package XHDWalletAPI

import (
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Algorand Go SDK compatibile wrapper with simplified path interface
type AlgoPath struct {
	w   *Wallet
	ctx KeyContext
	account,
	change,
	keyIndex uint32
}

// Path00 returns an AlgoPath for account 0, change 0 at the given key index.
// This is a convenience method for the most common derivation path m/44'/283'/0'/0/keyIndex.
func (w *Wallet) Path00(keyIndex uint32) AlgoPath {
	return AlgoPath{
		w:        w,
		ctx:      AlgoCoinType,
		account:  0,
		change:   0,
		keyIndex: keyIndex,
	}
}

// Path returns an AlgoPath for the given account, change, and key index,
// using the Algorand coin type (283) in the BIP-44 derivation path m/44'/283'/account'/change/keyIndex.
func (w *Wallet) Path(account, change, keyIndex uint32) AlgoPath {
	return AlgoPath{
		w:        w,
		ctx:      AlgoCoinType,
		account:  account,
		change:   change,
		keyIndex: keyIndex,
	}
}

// AlgorandAddress derives and returns the Algorand address for this path.
func (ap AlgoPath) AlgorandAddress() (types.Address, error) {
	pk, err := ap.w.AlgorandAddress(ap.account, ap.change, ap.keyIndex)
	if err != nil {
		return types.Address{}, err
	}
	var addr types.Address
	copy(addr[:], pk)
	return addr, nil
}

// SignData signs arbitrary data with the key at this path making sure that there is no known Algorand TX type prefix.
func (ap AlgoPath) SignData(data []byte) ([]byte, error) {
	return ap.w.SignData(ap.ctx, ap.account, ap.change, ap.keyIndex, data)
}

// SignBytes signs raw bytes with the key at this path, with no domain separator or prefix applied.
func (ap AlgoPath) SignBytes(data []byte) ([]byte, error) {
	return ap.w.SignBytes(ap.ctx, ap.account, ap.change, ap.keyIndex, data)
}

// SignTransaction returns the bytes of a signed transaction ready to be broadcasted to the network
// If the derived address is different than the txn sender's, the derived
// corresponding address will be assigned as AuthAddr
func (ap AlgoPath) SignTransaction(tx types.Transaction) (txid string, stxBytes []byte, err error) {
	toBeSigned := rawTransactionBytesToSign(tx)
	txid = txIDFromRawTxnBytesToSign(toBeSigned)
	signature, err := ap.w.SignAlgoTransaction(ap.ctx, ap.account, ap.change, ap.keyIndex, toBeSigned)
	if err != nil {
		return
	}
	var s types.Signature
	n := copy(s[:], signature)
	if n != len(s) {
		err = ErrInvalidSignature
		return
	}

	// Construct the SignedTxn
	stx := types.SignedTxn{
		Sig: s,
		Txn: tx,
	}

	a, err := ap.AlgorandAddress()
	if err != nil {
		return
	}

	if stx.Txn.Sender != a {
		stx.AuthAddr = a
	}

	// Encode the SignedTxn
	stxBytes = msgpack.Encode(stx)
	return
}
