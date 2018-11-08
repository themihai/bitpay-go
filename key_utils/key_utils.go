//Package key_utils provides methods to generate keys and retrieve bitpay specific ids (the SIN) and correctly formatted signatures.
package key_utils

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"

	"golang.org/x/crypto/ripemd160"
)

//This type provides compatibility with the btcec package
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

//All BitPay clients use a PEM file to store the private and public keys.
func GeneratePem() string {
	priv, _ := btcec.NewPrivateKey(btcec.S256())
	pub := priv.PubKey()
	ecd := pub.ToECDSA()
	oid := asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	curve := btcec.S256()
	der, _ := asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    priv.D.Bytes(),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(curve, ecd.X, ecd.Y)},
	})
	blck := pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	pm := pem.EncodeToMemory(&blck)
	return string(pm)
}

//GenerateSinFromPem returns a base58 encoding of a public key. It expects a pem string as the argument.
func GenerateSinFromPem(pm string) (string, error) {
	key, err := ExtractKeyFromPem(pm)
	if err != nil {
		return "", err
	}
	sin := generateSinFromKey(key)
	return sin, nil
}

//ExtractCompressedPublicKey returns a hexadecimal encoding of the compressed public key. It expects a pem string as the argument.
func ExtractCompressedPublicKey(pm string) (string, error) {
	key, err := ExtractKeyFromPem(pm)
	if err != nil {
		return "", err
	}
	pub := key.PubKey()
	comp := pub.SerializeCompressed()
	hexb := hex.EncodeToString(comp)
	return hexb, nil
}

//Returns a hexadecimal encoding of the signed sha256 hash of message, using the key provide in the pem string pm.
func Sign(message string, pm string) (string, error) {
	key, err := ExtractKeyFromPem(pm)
	if err != nil {
		return "", err
	}
	byta := []byte(message)
	hash := sha256.New()
	hash.Write(byta)
	bytb := hash.Sum(nil)
	sig, _ := key.Sign(bytb)
	ser := sig.Serialize()
	hexa := hex.EncodeToString(ser)
	return hexa, nil
}

//Returns a btec.Private key object if provided a correct secp256k1 encoded pem.
func ExtractKeyFromPem(pm string) (*btcec.PrivateKey, error) {
	byta := []byte(pm)
	blck, _ := pem.Decode(byta)
	if blck == nil {
		return nil, fmt.Errorf("No pem data found")
	}
	var ecp ecPrivateKey
	if _, err := asn1.Unmarshal(blck.Bytes, &ecp); err != nil {
		return nil, err
	}
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), ecp.PrivateKey)
	return priv, nil
}

func generateSinFromKey(key *btcec.PrivateKey) string {
	pub := key.PubKey()
	comp := pub.SerializeCompressed()
	hexb := hex.EncodeToString(comp)
	stx := generateSinFromPublicKey(hexb)
	return stx
}

func generateSinFromPublicKey(key string) string {
	hexa := sha256ofHexString(key)
	hexa = ripemd160ofHexString(hexa)
	versionSinTypeEtc := "0F02" + hexa
	hexa = sha256ofHexString(versionSinTypeEtc)
	hexa = sha256ofHexString(hexa)
	checksum := hexa[0:8]
	hexa = versionSinTypeEtc + checksum
	byta, _ := hex.DecodeString(hexa)
	sin := base58.Encode(byta)
	return sin
}

func sha256ofHexString(hexa string) string {
	byta, _ := hex.DecodeString(hexa)
	hash := sha256.New()
	hash.Write(byta)
	hashsum := hash.Sum(nil)
	hexb := hex.EncodeToString(hashsum)
	return hexb
}

func ripemd160ofHexString(hexa string) string {
	byta, _ := hex.DecodeString(hexa)
	hash := ripemd160.New()
	hash.Write(byta)
	hashsum := hash.Sum(nil)
	hexb := hex.EncodeToString(hashsum)
	return hexb
}
