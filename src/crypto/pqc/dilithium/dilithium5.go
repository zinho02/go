package dilithium

import (
	"crypto/pqc"
)

var signatureName = "dilithium5"

func GenerateKeyDilithium5() (*pqc.PrivateKey, error) {
	return pqc.GenerateKey(signatureName)
}

func VerifyDilithium5(data, signature []byte, pub *pqc.PublicKey) bool {
	return pqc.Verify(data, signature, pub, signatureName)
}
