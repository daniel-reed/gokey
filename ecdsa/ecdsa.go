package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
)

func KeyFromPem(pub, priv io.Reader) (*ecdsa.PrivateKey, error) {
	pubKey, err := PublicKeyFromPem(pub)
	if err != nil {
		return nil, err
	}
	privKey, err := PrivateKeyFromPem(priv)
	if err != nil {
		return nil, err
	}

	cPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to cast public key")
	}
	privKey.PublicKey = *cPubKey

	return privKey, nil
}

func PrivateKeyFromPem(r io.Reader) (*ecdsa.PrivateKey, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "read failure")
	}

	p, _ := pem.Decode(b)
	return x509.ParseECPrivateKey(p.Bytes)
}

func PublicKeyFromPem(r io.Reader) (interface{}, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "read failure")
	}
	p, _ := pem.Decode(b)
	return x509.ParsePKIXPublicKey(p.Bytes)
}

func New(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(c, rand.Reader)
}

func ToPem(key *ecdsa.PrivateKey) (pub []byte, priv []byte, err error) {
	pubB, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return pub, priv, err
	}
	privB, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return pub, priv, err
	}

	pub = pem.EncodeToMemory(
		&pem.Block{
			Type:  "ECDSA PUBLIC KEY",
			Bytes: pubB,
		},
	)

	priv = pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privB,
		},
	)

	return pub, priv, err
}
