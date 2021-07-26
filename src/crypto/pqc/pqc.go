package pqc

import (
	"bytes"
	"crypto"
	"io"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// PublicKey represents an PQC public key.
type PublicKey struct {
	AlgName string
	Bytes   []byte
}

// Equal reports whether public and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pub.Bytes, xx.Bytes) && pub.AlgName == xx.AlgName
}

// PrivateKey represents an PQC private key.
type PrivateKey struct {
	PublicKey
	Signer oqs.Signature
}

// Public returns the public key corresponding to private key.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) PQCPublic() *PublicKey {
	return priv.Public().(*PublicKey)
}

// Equal reports whether private and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && bytes.Equal(priv.Signer.ExportSecretKey(), xx.Signer.ExportSecretKey())
}

// Generates a key pair and returns the private key.
func GenerateKey(signatureName string) (*PrivateKey, error) {
	signer := oqs.Signature{}
	if err := signer.Init(signatureName, nil); err != nil {
		return nil, err
	}

	pubKeyBytes, err := signer.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	privKey := new(PrivateKey)
	privKey.AlgName = signatureName
	privKey.Bytes = pubKeyBytes
	privKey.Signer = signer

	return privKey, nil
}

/* Signs data and returns the signature.
rand and opts are not being used.
*/
func (priv *PrivateKey) Sign(rand io.Reader, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := priv.Signer.Sign(data)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Verifies the signature.
func Verify(data, signature []byte, pub *PublicKey, signatureName string) bool {
	verifier := oqs.Signature{}

	if err := verifier.Init(signatureName, nil); err != nil {
		return false
	}

	isValid, err := verifier.Verify(data, signature, (*pub).Bytes)
	if err != nil {
		return false
	}
	return isValid
}

// Verifies if the signature is supported.
func IsSigSupported(sig string) bool {
	return oqs.IsSigSupported(sig)
}

// Verifies if the signature is enabled.
func IsSigEnabled(sig string) bool {
	return oqs.IsSigEnabled(sig)
}
