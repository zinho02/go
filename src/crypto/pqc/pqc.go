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
	case "dilithium2":
		return OIDPublicKeyDilithium5
	case "dilithium2-aes":
		return OIDPublicKeyDilithium5AES
	case "falcon-512":
		return OIDPublicKeyFalcon1024
	case "rainbow-i-classic":
		return OIDPublicKeyRainbowIClassic
	case "rainbow-i-circumzenithal":
		return OIDPublicKeyRainbowICircumzenithal
	case "rainbow-i-compressed":
		return OIDPublicKeyRainbowICompressed
	case "sphincs+-haraka-128s-simple":
		return OIDPublicKeySphincsPlusHaraka128sSimple
	case "sphincs+-haraka-128f-simple":
		return OIDPublicKeySphincsPlusHaraka128fSimple
	case "sphincs+-haraka-128s-robust":
		return OIDPublicKeySphincsPlusHaraka128sRobust
	case "sphincs+-haraka-128f-robust":
		return OIDPublicKeySphincsPlusHaraka128fRobust
	case "sphincs+-sha256-128s-simple":
		return OIDPublicKeySphincsPlusSHA256128sSimple
	case "sphincs+-sha256-128f-simple":
		return OIDPublicKeySphincsPlusSHA256128fSimple
	case "sphincs+-sha256-128s-robust":
		return OIDPublicKeySphincsPlusSHA256128sRobust
	case "sphincs+-sha256-128f-robust":
		return OIDPublicKeySphincsPlusSHA256128fRobust
	case "sphincs+-shake256-128s-simple":
		return OIDPublicKeySphincsPlusSHAKE256128sSimple
	case "sphincs+-shake256-128f-simple":
		return OIDPublicKeySphincsPlusSHAKE256128fSimple
	case "sphincs+-shake256-128s-robust":
		return OIDPublicKeySphincsPlusSHAKE256128sRobust
	case "sphincs+-shake256-128f-robust":
		return OIDPublicKeySphincsPlusSHAKE256128fRobust
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
	case oid.Equal(OIDPublicKeyDilithium2):
		return "dilithium2"
	case oid.Equal(OIDPublicKeyDilithium2AES):
		return "dilithium2-aes"
	case oid.Equal(OIDPublicKeyFalcon512):
		return "falcon-512"
	case oid.Equal(OIDPublicKeyRainbowIClassic):
		return "rainbow-i-classic"
	case oid.Equal(OIDPublicKeyRainbowICircumzenithal):
		return "rainbow-i-circumzenithal"
	case oid.Equal(OIDPublicKeyRainbowICompressed):
		return "rainbow-i-compressed"
	case oid.Equal(OIDPublicKeySphincsPlusHaraka128sSimple):
		return "sphincs+-haraka-128s-simple"
	case oid.Equal(OIDPublicKeySphincsPlusHaraka128fSimple):
		return "sphincs+-haraka-128f-simple"
	case oid.Equal(OIDPublicKeySphincsPlusHaraka128sRobust):
		return "sphincs+-haraka-128s-robust"
	case oid.Equal(OIDPublicKeySphincsPlusHaraka128fRobust):
		return "sphincs+-haraka-128f-robust"
	case oid.Equal(OIDPublicKeySphincsPlusSHA256128sSimple):
		return "sphincs+-sha256-128s-simple"
	case oid.Equal(OIDPublicKeySphincsPlusSHA256128fSimple):
		return "sphincs+-sha256-128f-simple"
	case oid.Equal(OIDPublicKeySphincsPlusSHA256128sRobust):
		return "sphincs+-sha256-128s-robust"
	case oid.Equal(OIDPublicKeySphincsPlusSHA256128fRobust):
		return "sphincs+-sha256-128f-robust"
	case oid.Equal(OIDPublicKeySphincsPlusSHAKE256128sSimple):
		return "sphincs+-shake256-128s-simple"
	case oid.Equal(OIDPublicKeySphincsPlusSHAKE256128fSimple):
		return "sphincs+-shake256-128f-simple"
	case oid.Equal(OIDPublicKeySphincsPlusSHAKE256128sRobust):
		return "sphincs+-shake256-128s-robust"
	case oid.Equal(OIDPublicKeySphincsPlusSHAKE256128fRobust):
		return "sphincs+-shake256-128f-robust"
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
	case "dilithium2":
		return OIDSignatureDilithium5
	case "dilithium2-aes":
		return OIDSignatureDilithium5AES
	case "falcon-512":
		return OIDSignatureFalcon1024
	case "rainbow-i-classic":
		return OIDSignatureRainbowIClassic
	case "rainbow-i-circumzenithal":
		return OIDSignatureRainbowICircumzenithal
	case "rainbow-i-compressed":
		return OIDSignatureRainbowICompressed
	case "sphincs+-haraka-128s-simple":
		return OIDSignatureSphincsPlusHaraka128sSimple
	case "sphincs+-haraka-128f-simple":
		return OIDSignatureSphincsPlusHaraka128fSimple
	case "sphincs+-haraka-128s-robust":
		return OIDSignatureSphincsPlusHaraka128sRobust
	case "sphincs+-haraka-128f-robust":
		return OIDSignatureSphincsPlusHaraka128fRobust
	case "sphincs+-sha256-128s-simple":
		return OIDSignatureSphincsPlusSHA256128sSimple
	case "sphincs+-sha256-128f-simple":
		return OIDSignatureSphincsPlusSHA256128fSimple
	case "sphincs+-sha256-128s-robust":
		return OIDSignatureSphincsPlusSHA256128sRobust
	case "sphincs+-sha256-128f-robust":
		return OIDSignatureSphincsPlusSHA256128fRobust
	case "sphincs+-shake256-128s-simple":
		return OIDSignatureSphincsPlusSHAKE256128sSimple
	case "sphincs+-shake256-128f-simple":
		return OIDSignatureSphincsPlusSHAKE256128fSimple
	case "sphincs+-shake256-128s-robust":
		return OIDSignatureSphincsPlusSHAKE256128sRobust
	case "sphincs+-shake256-128f-robust":
		return OIDSignatureSphincsPlusSHAKE256128fRobust
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
	case oid.Equal(OIDSignatureDilithium2):
		return "dilithium2"
	case oid.Equal(OIDSignatureDilithium2AES):
		return "dilithium2-aes"
	case oid.Equal(OIDSignatureFalcon512):
		return "falcon-512"
	case oid.Equal(OIDSignatureRainbowIClassic):
		return "rainbow-i-classic"
	case oid.Equal(OIDSignatureRainbowICircumzenithal):
		return "rainbow-i-circumzenithal"
	case oid.Equal(OIDSignatureRainbowICompressed):
		return "rainbow-i-compressed"
	case oid.Equal(OIDSignatureSphincsPlusHaraka128sSimple):
		return "sphincs+-haraka-128s-simple"
	case oid.Equal(OIDSignatureSphincsPlusHaraka128fSimple):
		return "sphincs+-haraka-128f-simple"
	case oid.Equal(OIDSignatureSphincsPlusHaraka128sRobust):
		return "sphincs+-haraka-128s-robust"
	case oid.Equal(OIDSignatureSphincsPlusHaraka128fRobust):
		return "sphincs+-haraka-128f-robust"
	case oid.Equal(OIDSignatureSphincsPlusSHA256128sSimple):
		return "sphincs+-sha256-128s-simple"
	case oid.Equal(OIDSignatureSphincsPlusSHA256128fSimple):
		return "sphincs+-sha256-128f-simple"
	case oid.Equal(OIDSignatureSphincsPlusSHA256128sRobust):
		return "sphincs+-sha256-128s-robust"
	case oid.Equal(OIDSignatureSphincsPlusSHA256128fRobust):
		return "sphincs+-sha256-128f-robust"
	case oid.Equal(OIDSignatureSphincsPlusSHAKE256128sSimple):
		return "sphincs+-shake256-128s-simple"
	case oid.Equal(OIDSignatureSphincsPlusSHAKE256128fSimple):
		return "sphincs+-shake256-128f-simple"
	case oid.Equal(OIDSignatureSphincsPlusSHAKE256128sRobust):
		return "sphincs+-shake256-128s-robust"
	case oid.Equal(OIDSignatureSphincsPlusSHAKE256128fRobust):
		return "sphincs+-shake256-128f-robust"
	default:
		return ""
	}
}

var (
	OIDPublicKeyDilithium5                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7}
	OIDPublicKeyFalcon1024                    = asn1.ObjectIdentifier{1, 3, 9999, 3, 4}
	OIDPublicKeyDilithium5AES                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 11, 8, 7}
	OIDPublicKeyRainbowVClassic               = asn1.ObjectIdentifier{1, 3, 9999, 5, 3, 1, 1}
	OIDPublicKeyRainbowVCircumzenithal        = asn1.ObjectIdentifier{1, 3, 9999, 5, 3, 3, 1}
	OIDPublicKeyRainbowVCompressed            = asn1.ObjectIdentifier{1, 3, 9999, 5, 3, 5, 1}
	OIDPublicKeySphincsPlusHaraka256sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 3, 7}
	OIDPublicKeySphincsPlusHaraka256fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 3, 3}
	OIDPublicKeySphincsPlusHaraka256sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 3, 5}
	OIDPublicKeySphincsPlusHaraka256fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 3, 1}
	OIDPublicKeySphincsPlusSHA256256sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 13}
	OIDPublicKeySphincsPlusSHA256256fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 7}
	OIDPublicKeySphincsPlusSHA256256sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 5}
	OIDPublicKeySphincsPlusSHA256256fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 1}
	OIDPublicKeySphincsPlusSHAKE256256sSimple = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 7}
	OIDPublicKeySphincsPlusSHAKE256256fSimple = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 3}
	OIDPublicKeySphincsPlusSHAKE256256sRobust = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 5}
	OIDPublicKeySphincsPlusSHAKE256256fRobust = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 1}
	OIDPublicKeyDilithium2                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 4, 4}
	OIDPublicKeyFalcon512                     = asn1.ObjectIdentifier{1, 3, 9999, 3, 1}
	OIDPublicKeyDilithium2AES                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 11, 4, 4}
	OIDPublicKeyRainbowIClassic               = asn1.ObjectIdentifier{1, 3, 9999, 5, 1, 1, 1}
	OIDPublicKeyRainbowICircumzenithal        = asn1.ObjectIdentifier{1, 3, 9999, 5, 1, 1, 1}
	OIDPublicKeyRainbowICompressed            = asn1.ObjectIdentifier{1, 3, 9999, 5, 1, 7, 1}
	OIDPublicKeySphincsPlusHaraka128sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 10}
	OIDPublicKeySphincsPlusHaraka128fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 4}
	OIDPublicKeySphincsPlusHaraka128sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 7}
	OIDPublicKeySphincsPlusHaraka128fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 1}
	OIDPublicKeySphincsPlusSHA256128sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 10}
	OIDPublicKeySphincsPlusSHA256128fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 4}
	OIDPublicKeySphincsPlusSHA256128sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 7}
	OIDPublicKeySphincsPlusSHA256128fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 1}
	OIDPublicKeySphincsPlusSHAKE256128sSimple = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 10}
	OIDPublicKeySphincsPlusSHAKE256128fSimple = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 4}
	OIDPublicKeySphincsPlusSHAKE256128sRobust = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 7}
	OIDPublicKeySphincsPlusSHAKE256128fRobust = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 1}
)

var (
	OIDSignatureDilithium5                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7}
	OIDSignatureFalcon1024                    = asn1.ObjectIdentifier{1, 3, 9999, 3, 4}
	OIDSignatureDilithium5AES                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 11, 8, 7}
	OIDSignatureRainbowVClassic               = asn1.ObjectIdentifier{1, 3, 9999, 5, 3, 1, 1}
	OIDSignatureRainbowVCircumzenithal        = asn1.ObjectIdentifier{1, 3, 9999, 5, 3, 3, 1}
	OIDSignatureRainbowVCompressed            = asn1.ObjectIdentifier{1, 3, 9999, 5, 3, 5, 1}
	OIDSignatureSphincsPlusHaraka256sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 3, 7}
	OIDSignatureSphincsPlusHaraka256fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 3, 3}
	OIDSignatureSphincsPlusHaraka256sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 3, 5}
	OIDSignatureSphincsPlusHaraka256fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 3, 1}
	OIDSignatureSphincsPlusSHA256256sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 3, 13}
	OIDSignatureSphincsPlusSHA256256fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 7}
	OIDSignatureSphincsPlusSHA256256sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 5}
	OIDSignatureSphincsPlusSHA256256fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 6, 1}
	OIDSignatureSphincsPlusSHAKE256256sSimple = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 7}
	OIDSignatureSphincsPlusSHAKE256256fSimple = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 3}
	OIDSignatureSphincsPlusSHAKE256256sRobust = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 5}
	OIDSignatureSphincsPlusSHAKE256256fRobust = asn1.ObjectIdentifier{1, 3, 9999, 6, 9, 1}
	OIDSignatureDilithium2                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 4, 4}
	OIDSignatureFalcon512                     = asn1.ObjectIdentifier{1, 3, 9999, 3, 1}
	OIDSignatureDilithium2AES                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 11, 4, 4}
	OIDSignatureRainbowIClassic               = asn1.ObjectIdentifier{1, 3, 9999, 5, 1, 1, 1}
	OIDSignatureRainbowICircumzenithal        = asn1.ObjectIdentifier{1, 3, 9999, 5, 1, 1, 1}
	OIDSignatureRainbowICompressed            = asn1.ObjectIdentifier{1, 3, 9999, 5, 1, 7, 1}
	OIDSignatureSphincsPlusHaraka128sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 10}
	OIDSignatureSphincsPlusHaraka128fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 4}
	OIDSignatureSphincsPlusHaraka128sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 7}
	OIDSignatureSphincsPlusHaraka128fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 1}
	OIDSignatureSphincsPlusSHA256128sSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 10}
	OIDSignatureSphincsPlusSHA256128fSimple   = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 4}
	OIDSignatureSphincsPlusSHA256128sRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 7}
	OIDSignatureSphincsPlusSHA256128fRobust   = asn1.ObjectIdentifier{1, 3, 9999, 6, 4, 1}
	OIDSignatureSphincsPlusSHAKE256128sSimple = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 10}
	OIDSignatureSphincsPlusSHAKE256128fSimple = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 4}
	OIDSignatureSphincsPlusSHAKE256128sRobust = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 7}
	OIDSignatureSphincsPlusSHAKE256128fRobust = asn1.ObjectIdentifier{1, 3, 9999, 6, 7, 1}
)
