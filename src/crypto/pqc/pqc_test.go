package pqc_test

import (
	"crypto/pqc"
	"testing"

	"github.com/stretchr/testify/assert"
)

var alg string = "dilithium5"

var msg string = "Sign this."

func generateKey() (*pqc.PrivateKey, error) {
	return pqc.GenerateKey(alg)
}

func TestGenerateKey(t *testing.T) {
	privKey, _ := pqc.GenerateKey(alg)
	assert.Equal(t, alg, privKey.AlgName)
}

func TestPrivateKeyEqual(t *testing.T) {
	privKey, _ := generateKey()
	assert.True(t, privKey.Equal(privKey))
}

func TestPublicKeyEqual(t *testing.T) {
	privKey, _ := generateKey()
	pubKey := privKey.PQCPublic()
	assert.True(t, pubKey.Equal(pubKey))
}

func TestPublic(t *testing.T) {
	privKey, _ := generateKey()
	pubKey := privKey.PQCPublic()
	assert.Equal(t, alg, pubKey.AlgName)
	assert.Equal(t, privKey.Bytes, pubKey.Bytes)
}

func TestPQCPublic(t *testing.T) {
	privKey, _ := generateKey()
	pubKey := privKey.PQCPublic()
	pqcPubKey := new(pqc.PublicKey)
	assert.IsType(t, pqcPubKey, pubKey)
}

func TestSign(t *testing.T) {
	privKey, _ := generateKey()
	sig, _ := privKey.Sign(nil, []byte(msg), nil)
	assert.NotNil(t, sig)
}

func TestVerify(t *testing.T) {
	privKey, _ := generateKey()
	sig, _ := privKey.Sign(nil, []byte(msg), nil)
	pubKey := privKey.PQCPublic()
	verifyTest := pubKey.Verify([]byte(msg), sig)
	assert.True(t, verifyTest)
}
