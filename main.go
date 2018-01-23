package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"flag"
	ec "github.com/daniel-reed/gokey/ecdsa"
	r "github.com/daniel-reed/gokey/rsa"
	"io/ioutil"
)

var (
	t = flag.String("type", "", "key type")
	b = flag.Int("size", 0, "key size")
	o = flag.String("out", "", "output file")
)

func main() {
	flag.Parse()
	switch *t {
	case "ecdsa":
		if *o == "" {
			*o = "id_ecdsa"
		}
		curve := elliptic.P256()
		switch *b {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		}

		k, err := ec.New(curve)
		if err != nil {
			panic(err)
		}
		if err = writeEcdsa(k); err != nil {
			panic(err)
		}
	case "rsa":
		if *o == "" {
			*o = "id_rsa"
		}
		var bits r.KeySize = r.RSA256
		switch *b {
		case 128:
			bits = r.RSA128
		case 256:
			bits = r.RSA256
		case 512:
			bits = r.RSA512
		}
		k, err := r.New(bits)
		if err != nil {
			panic(err)
		}
		if err = writeRsa(k); err != nil {
			panic(err)
		}
	}

}

func writeEcdsa(k *ecdsa.PrivateKey) error {
	pub, priv, err := ec.ToPem(k)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(*o+".pub", pub, 0644)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(*o, priv, 0600)
	if err != nil {
		return err
	}

	return nil
}

func writeRsa(k *rsa.PrivateKey) error {
	pub, priv, err := r.ToPem(k)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(*o+".pub", pub, 0644)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(*o, priv, 0600)
	if err != nil {
		return err
	}

	return nil
}
