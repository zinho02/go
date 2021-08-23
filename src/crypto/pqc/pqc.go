package pqc

import (
	"bytes"
	"crypto"
	"encoding/asn1"
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
func (pub *PublicKey) Verify(data, signature []byte) bool {
	verifier := oqs.Signature{}

	if err := verifier.Init(pub.AlgName, nil); err != nil {
		return false
	}

	isValid, err := verifier.Verify(data, signature, (*pub).Bytes)
	if err != nil {
		return false
	}
	return isValid
}

func GetPublicKeyOIDFromPublicKey(algName string) asn1.ObjectIdentifier {
	switch algName {
	case "dilithium5":
		return OIDPublicKeyDilithium5
	case "dilithium5-aes":
		return OIDPublicKeyDilithium5AES
	case "falcon-1024":
		return OIDPublicKeyFalcon1024
	case "rainbow-v-classic":
		return OIDPublicKeyRainbowVClassic
	case "rainbow-v-circumzenithal":
		return OIDPublicKeyRainbowVCircumzenithal
	case "rainbow-v-compressed":
		return OIDPublicKeyRainbowVCompressed
	case "sphincs+-haraka-256s-simple":
		return OIDPublicKeySphincsPlusHaraka256sSimple
	case "sphincs+-haraka-256f-simple":
		return OIDPublicKeySphincsPlusHaraka256fSimple
	case "sphincs+-haraka-256s-robust":
		return OIDPublicKeySphincsPlusHaraka256sRobust
	case "sphincs+-haraka-256f-robust":
		return OIDPublicKeySphincsPlusHaraka256fRobust
	case "sphincs+-sha256-256s-simple":
		return OIDPublicKeySphincsPlusSHA256256sSimple
	case "sphincs+-sha256-256f-simple":
		return OIDPublicKeySphincsPlusSHA256256fSimple
	case "sphincs+-sha256-256s-robust":
		return OIDPublicKeySphincsPlusSHA256256sRobust
	case "sphincs+-sha256-256f-robust":
		return OIDPublicKeySphincsPlusSHA256256fRobust
	case "sphincs+-shake256-256s-simple":
		return OIDPublicKeySphincsPlusSHAKE256256sSimple
	case "sphincs+-shake256-256f-simple":
		return OIDPublicKeySphincsPlusSHAKE256256fSimple
	case "sphincs+-shake256-256s-robust":
		return OIDPublicKeySphincsPlusSHAKE256256sRobust
	case "sphincs+-shake256-256f-robust":
		return OIDPublicKeySphincsPlusSHAKE256256fRobust
	default:
		return nil
	}
}

func GetPublicKeyFromPublicKeyOID(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(OIDPublicKeyDilithium5):
		return "dilithium5"
	case oid.Equal(OIDPublicKeyDilithium5AES):
		return "dilithium5-aes"
	case oid.Equal(OIDPublicKeyFalcon1024):
		return "falcon-1024"
	case oid.Equal(OIDPublicKeyRainbowVClassic):
		return "rainbow-v-classic"
	case oid.Equal(OIDPublicKeyRainbowVCircumzenithal):
		return "rainbow-v-circumzenithal"
	case oid.Equal(OIDPublicKeyRainbowVCompressed):
		return "rainbow-v-compressed"
	case oid.Equal(OIDPublicKeySphincsPlusHaraka256sSimple):
		return "sphincs+-haraka-256s-simple"
	case oid.Equal(OIDPublicKeySphincsPlusHaraka256fSimple):
		return "sphincs+-haraka-256f-simple"
	case oid.Equal(OIDPublicKeySphincsPlusHaraka256sRobust):
		return "sphincs+-haraka-256s-robust"
	case oid.Equal(OIDPublicKeySphincsPlusHaraka256fRobust):
		return "sphincs+-haraka-256f-robust"
	case oid.Equal(OIDPublicKeySphincsPlusSHA256256sSimple):
		return "sphincs+-sha256-256s-simple"
	case oid.Equal(OIDPublicKeySphincsPlusSHA256256fSimple):
		return "sphincs+-sha256-256f-simple"
	case oid.Equal(OIDPublicKeySphincsPlusSHA256256sRobust):
		return "sphincs+-sha256-256s-robust"
	case oid.Equal(OIDPublicKeySphincsPlusSHA256256fRobust):
		return "sphincs+-sha256-256f-robust"
	case oid.Equal(OIDPublicKeySphincsPlusSHAKE256256sSimple):
		return "sphincs+-shake256-256s-simple"
	case oid.Equal(OIDPublicKeySphincsPlusSHAKE256256fSimple):
		return "sphincs+-shake256-256f-simple"
	case oid.Equal(OIDPublicKeySphincsPlusSHAKE256256sRobust):
		return "sphincs+-shake256-256s-robust"
	case oid.Equal(OIDPublicKeySphincsPlusSHAKE256256fRobust):
		return "sphincs+-shake256-256f-robust"
	default:
		return ""
	}
}

func GetSignatureOIDFromPublicKey(algName string) asn1.ObjectIdentifier {
	switch algName {
	case "dilithium5":
		return OIDSignatureDilithium5
	case "dilithium5-aes":
		return OIDSignatureDilithium5AES
	case "falcon-1024":
		return OIDSignatureFalcon1024
	case "rainbow-v-classic":
		return OIDSignatureRainbowVClassic
	case "rainbow-v-circumzenithal":
		return OIDSignatureRainbowVCircumzenithal
	case "rainbow-v-compressed":
		return OIDSignatureRainbowVCompressed
	case "sphincs+-haraka-256s-simple":
		return OIDSignatureSphincsPlusHaraka256sSimple
	case "sphincs+-haraka-256f-simple":
		return OIDSignatureSphincsPlusHaraka256fSimple
	case "sphincs+-haraka-256s-robust":
		return OIDSignatureSphincsPlusHaraka256sRobust
	case "sphincs+-haraka-256f-robust":
		return OIDSignatureSphincsPlusHaraka256fRobust
	case "sphincs+-sha256-256s-simple":
		return OIDSignatureSphincsPlusSHA256256sSimple
	case "sphincs+-sha256-256f-simple":
		return OIDSignatureSphincsPlusSHA256256fSimple
	case "sphincs+-sha256-256s-robust":
		return OIDSignatureSphincsPlusSHA256256sRobust
	case "sphincs+-sha256-256f-robust":
		return OIDSignatureSphincsPlusSHA256256fRobust
	case "sphincs+-shake256-256s-simple":
		return OIDSignatureSphincsPlusSHAKE256256sSimple
	case "sphincs+-shake256-256f-simple":
		return OIDSignatureSphincsPlusSHAKE256256fSimple
	case "sphincs+-shake256-256s-robust":
		return OIDSignatureSphincsPlusSHAKE256256sRobust
	case "sphincs+-shake256-256f-robust":
		return OIDSignatureSphincsPlusSHAKE256256fRobust
	default:
		return nil
	}
}

func GetPublicKeyFromSignatureOID(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(OIDSignatureDilithium5):
		return "dilithium5"
	case oid.Equal(OIDSignatureDilithium5AES):
		return "dilithium5-aes"
	case oid.Equal(OIDSignatureFalcon1024):
		return "falcon-1024"
	case oid.Equal(OIDSignatureRainbowVClassic):
		return "rainbow-v-classic"
	case oid.Equal(OIDSignatureRainbowVCircumzenithal):
		return "rainbow-v-circumzenithal"
	case oid.Equal(OIDSignatureRainbowVCompressed):
		return "rainbow-v-compressed"
	case oid.Equal(OIDSignatureSphincsPlusHaraka256sSimple):
		return "sphincs+-haraka-256s-simple"
	case oid.Equal(OIDSignatureSphincsPlusHaraka256fSimple):
		return "sphincs+-haraka-256f-simple"
	case oid.Equal(OIDSignatureSphincsPlusHaraka256sRobust):
		return "sphincs+-haraka-256s-robust"
	case oid.Equal(OIDSignatureSphincsPlusHaraka256fRobust):
		return "sphincs+-haraka-256f-robust"
	case oid.Equal(OIDSignatureSphincsPlusSHA256256sSimple):
		return "sphincs+-sha256-256s-simple"
	case oid.Equal(OIDSignatureSphincsPlusSHA256256fSimple):
		return "sphincs+-sha256-256f-simple"
	case oid.Equal(OIDSignatureSphincsPlusSHA256256sRobust):
		return "sphincs+-sha256-256s-robust"
	case oid.Equal(OIDSignatureSphincsPlusSHA256256fRobust):
		return "sphincs+-sha256-256f-robust"
	case oid.Equal(OIDSignatureSphincsPlusSHAKE256256sSimple):
		return "sphincs+-shake256-256s-simple"
	case oid.Equal(OIDSignatureSphincsPlusSHAKE256256fSimple):
		return "sphincs+-shake256-256f-simple"
	case oid.Equal(OIDSignatureSphincsPlusSHAKE256256sRobust):
		return "sphincs+-shake256-256s-robust"
	case oid.Equal(OIDSignatureSphincsPlusSHAKE256256fRobust):
		return "sphincs+-shake256-256f-robust"
	default:
		return ""
	}
}

var (
	OIDPublicKeyDilithium5                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 6, 7}
	OIDPublicKeyFalcon1024                    = asn1.ObjectIdentifier{1, 3, 9999, 3, 4}
	OIDPublicKeyDilithium5AES                 = asn1.ObjectIdentifier{1, 3, 9999, 3, 5}
	OIDPublicKeyRainbowVClassic               = asn1.ObjectIdentifier{1, 3, 9999, 3, 6}
	OIDPublicKeyRainbowVCircumzenithal        = asn1.ObjectIdentifier{1, 3, 9999, 3, 7}
	OIDPublicKeyRainbowVCompressed            = asn1.ObjectIdentifier{1, 3, 9999, 3, 8}
	OIDPublicKeySphincsPlusHaraka256sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 9}
	OIDPublicKeySphincsPlusHaraka256fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 10}
	OIDPublicKeySphincsPlusHaraka256sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 3, 11}
	OIDPublicKeySphincsPlusHaraka256fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 3, 12}
	OIDPublicKeySphincsPlusSHA256256sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 13}
	OIDPublicKeySphincsPlusSHA256256fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 14}
	OIDPublicKeySphincsPlusSHA256256sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 3, 15}
	OIDPublicKeySphincsPlusSHA256256fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 3, 16}
	OIDPublicKeySphincsPlusSHAKE256256sSimple = asn1.ObjectIdentifier{1, 3, 9999, 3, 17}
	OIDPublicKeySphincsPlusSHAKE256256fSimple = asn1.ObjectIdentifier{1, 3, 9999, 3, 18}
	OIDPublicKeySphincsPlusSHAKE256256sRobust = asn1.ObjectIdentifier{1, 3, 9999, 3, 19}
	OIDPublicKeySphincsPlusSHAKE256256fRobust = asn1.ObjectIdentifier{1, 3, 9999, 3, 20}
)

var (
	OIDSignatureDilithium5                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 6, 7}
	OIDSignatureFalcon1024                    = asn1.ObjectIdentifier{1, 3, 9999, 3, 4}
	OIDSignatureDilithium5AES                 = asn1.ObjectIdentifier{1, 3, 9999, 3, 5}
	OIDSignatureRainbowVClassic               = asn1.ObjectIdentifier{1, 3, 9999, 3, 6}
	OIDSignatureRainbowVCircumzenithal        = asn1.ObjectIdentifier{1, 3, 9999, 3, 7}
	OIDSignatureRainbowVCompressed            = asn1.ObjectIdentifier{1, 3, 9999, 3, 8}
	OIDSignatureSphincsPlusHaraka256sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 9}
	OIDSignatureSphincsPlusHaraka256fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 10}
	OIDSignatureSphincsPlusHaraka256sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 3, 11}
	OIDSignatureSphincsPlusHaraka256fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 3, 12}
	OIDSignatureSphincsPlusSHA256256sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 13}
	OIDSignatureSphincsPlusSHA256256fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 14}
	OIDSignatureSphincsPlusSHA256256sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 3, 15}
	OIDSignatureSphincsPlusSHA256256fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 3, 16}
	OIDSignatureSphincsPlusSHAKE256256sSimple = asn1.ObjectIdentifier{1, 3, 9999, 3, 17}
	OIDSignatureSphincsPlusSHAKE256256fSimple = asn1.ObjectIdentifier{1, 3, 9999, 3, 18}
	OIDSignatureSphincsPlusSHAKE256256sRobust = asn1.ObjectIdentifier{1, 3, 9999, 3, 19}
	OIDSignatureSphincsPlusSHAKE256256fRobust = asn1.ObjectIdentifier{1, 3, 9999, 3, 20}
)
