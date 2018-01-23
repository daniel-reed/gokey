package ecdsa

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	key, err := New(elliptic.P256())
	if err != nil {
		t.Errorf("call to New() failed: %q", err.Error())
	}

	_, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Errorf("invalid public key: %q", err.Error())
	}

	_, err = x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Errorf("invalid private key: %q", err.Error())
	}
}

func TestPrivateKeyFromPem(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "test_keys", "id_ecdsa"))
	if err != nil {
		t.Errorf("failed to open test_keys key: %q", err.Error())
	}

	_, err = PrivateKeyFromPem(f)
	if err != nil {
		t.Errorf("failed to read key: %q", err.Error())
	}
}

func TestPublicKeyFromPem(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "test_keys", "id_ecdsa.pub"))
	if err != nil {
		t.Errorf("failed to open test_keys key: %q", err.Error())
	}

	_, err = PublicKeyFromPem(f)
	if err != nil {
		t.Errorf("failed to read key: %q", err.Error())
	}
}

func TestKeyFromPem(t *testing.T) {
	privf, err := os.Open(filepath.Join("..", "test_keys", "id_rsa"))
	if err != nil {
		t.Errorf("failed to open test_keys key: %q", err.Error())
	}
	defer privf.Close()

	pubf, err := os.Open(filepath.Join("..", "test_keys", "id_rsa.pub"))
	if err != nil {
		t.Errorf("failed to open test_keys key: %q", err.Error())
	}
	defer pubf.Close()

	_, err = KeyFromPem(pubf, privf)
	if err != nil {
		t.Errorf("failed to convert test_keys key: %q", err.Error())
	}
}

func TestToPem(t *testing.T) {
	pubb, err := ioutil.ReadFile(filepath.Join("..", "test_keys", "id_ecdsa.pub"))
	if err != nil {
		t.Error("failed to read test_keys key")
	}
	pubf, err := os.Open(filepath.Join("..", "test_keys", "id_ecdsa.pub"))
	if err != nil {
		t.Errorf("failed to open test_keys key: %q", err.Error())
	}
	defer pubf.Close()

	privb, err := ioutil.ReadFile(filepath.Join("..", "test_keys", "id_ecdsa"))
	if err != nil {
		t.Error("failed to read test_keys key")
	}
	privf, err := os.Open(filepath.Join("..", "test_keys", "id_ecdsa"))
	if err != nil {
		t.Errorf("failed to open test_keys key: %q", err.Error())
	}
	defer pubf.Close()

	privk, err := KeyFromPem(pubf, privf)
	if err != nil {
		t.Errorf("failed to convert test_keys key: %q", err.Error())
	}

	npubb, nprivb, err := ToPem(privk)
	if err != nil {
		t.Errorf("failed to write pem: %q", err.Error())
	}

	if bytes.Compare(privb, nprivb) != 0 {
		t.Errorf("private key bytes do not match\n\n%s\n%s\n", privb, nprivb)
	}

	if bytes.Compare(pubb, npubb) != 0 {
		t.Errorf("public key bytes do not match\n\n%s\n%s\n", pubb, npubb)
	}
}
