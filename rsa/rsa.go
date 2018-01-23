package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
)

type KeySize int

const (
	RSA128 = 128 * 8
	RSA256 = 256 * 8
	RSA512 = 512 * 8
)

func KeyFromPem(pub, priv io.Reader) (*rsa.PrivateKey, error) {
	pubKey, err := PublicKeyFromPem(pub)
	if err != nil {
		return nil, err
	}
	privKey, err := PrivateKeyFromPem(priv)
	if err != nil {
		return nil, err
	}

	cPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to cast public key")
	}
	privKey.PublicKey = *cPubKey

	return privKey, nil
}

func PrivateKeyFromPem(r io.Reader) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "read failure")
	}
	p, _ := pem.Decode(b)
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

func PublicKeyFromPem(r io.Reader) (interface{}, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "read failure")
	}
	p, _ := pem.Decode(b)
	return x509.ParsePKIXPublicKey(p.Bytes)
}

func New(n KeySize) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, int(n))
}

func ToPem(key *rsa.PrivateKey) (pub []byte, priv []byte, err error) {
	pubB, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return pub, priv, err
	}
	privB := x509.MarshalPKCS1PrivateKey(key)

	pub = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubB,
	})

	priv = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privB,
	})

	return
}
