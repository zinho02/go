// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/pqc"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	PublicKey  []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, or a ed25519.PrivateKey.
// More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium5):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyDilithium5)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium5AES):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyDilithium5AES)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyFalcon1024):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyFalcon1024)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowVClassic):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyRainbowVClassic)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowVCircumzenithal):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyRainbowVCircumzenithal)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowVCompressed):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyRainbowVCompressed)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusHaraka256sSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusHaraka256sSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusHaraka256fSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusHaraka256fSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusHaraka256sRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusHaraka256sRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusHaraka256fRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusHaraka256fRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHA256256sSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHA256256sSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHA256256fSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHA256256fSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHA256256sRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHA256256sRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHA256256fRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHA256256fRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHAKE256256sSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHAKE256256sSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHAKE256256fSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHAKE256256fSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHAKE256256sRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHAKE256256sRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHAKE256256fRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHAKE256256fRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium2):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyDilithium2)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium2AES):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyDilithium2AES)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyFalcon512):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyFalcon512)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowIClassic):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyRainbowIClassic)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowICircumzenithal):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyRainbowICircumzenithal)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowICompressed):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeyRainbowICompressed)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusHaraka128sSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusHaraka128sSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusHaraka128fSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusHaraka128fSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusHaraka128sRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusHaraka128sRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusHaraka128fRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusHaraka128fRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHA256128sSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHA256128sSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHA256128fSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHA256128fSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHA256128sRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHA256128sRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHA256128fRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHA256128fRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHAKE256128sSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHAKE256128sSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHAKE256128fSimple):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHAKE256128fSimple)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHAKE256128sRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHAKE256128sRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeySphincsPlusSHAKE256128fRobust):
		algName := pqc.GetPublicKeyFromPublicKeyOID(oidPublicKeySphincsPlusSHAKE256128fRobust)
		key := pqc.PrivateKey{
			PublicKey: pqc.PublicKey{
				Bytes:   privKey.PublicKey,
				AlgName: algName,
			},
		}
		key.Signer.Init(algName, privKey.PrivateKey)
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil

	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey, *ecdsa.PrivateKey
// and ed25519.PrivateKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)
	case *pqc.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  pqc.GetPublicKeyOIDFromPublicKey(k.AlgName),
			Parameters: asn1.NullRawValue,
		}
		privKey.PublicKey = k.Bytes
		privKey.PrivateKey = k.Signer.ExportSecretKey()
	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	default:
		return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}
