package dilithium

import (
	"crypto/pqc"
)

var signatureName = "dilithium5"

func GenerateKeyDilithium() (*pqc.PrivateKey, error) {
	return pqc.GenerateKey(signatureName)
}

func VerifyDilithium(data, signature []byte, pub *pqc.PublicKey) bool {
	return pqc.Verify(data, signature, pub, signatureName)
}
