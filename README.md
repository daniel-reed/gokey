# Gokey

Gokey is a small library to assist with reading and writing PEM ecdsa and rsa public and private keys

##Usage

### Command Line
```
gokey --type rsa --size 512 --out rsa_id
gokey --type ecdsa --size 256 --out ecdsa_id
```

### As a Library
```go
package main

import "os"
import "fmt"
import "crypto/elliptic" 
import "io/ioutil"
import "github.com/daniel-reed/gokey/ecdsa"
import "github.com/daniel-reed/gokey/rsa"

func main() {
	// Create keys
	ekey, _ := ecdsa.New(elliptic.P256())
	rkey, _ := rsa.New(rsa.RSA512)
	
	// Convert keys to bytes
	ekPublicBytes, ekPrivateBytes, _ := ecdsa.ToPem(ekey)
	rsaPublicBytes, rsaPrivateBytes, _ := rsa.ToPem(rkey)
	
	// Write key bytes to pem files
	ioutil.WriteFile("id_ecdsa.pub", ekPublicBytes, 0644)
	ioutil.WriteFile("id_ecdsa", ekPrivateBytes, 0600)
	ioutil.WriteFile("id_rsa.pub", rsaPublicBytes, 0644)
	ioutil.WriteFile("id_rsa", rsaPrivateBytes, 0600)
	
	// Read ecdsa key from disc
	ePubFile, _ := os.Open("id_ecdsa.pub")
	defer ePubFile.Close()
	ePrivFile, _ := os.Open("id_ecdsa")
	defer ePrivFile.Close()
	ePrivKey, _ := ecdsa.KeyFromPem(ePubFile, ePrivFile)
	fmt.Printf("ECDSA Key: %v", ePrivKey)
	
	// Read rsa key from disc
	rPubFile, _ := os.Open("id_rsa.pub")
	defer rPubFile.Close()
	rPrivFile, _ := os.Open("id_rsa")
	defer rPrivFile.Close()
	rPrivKey, _ := rsa.KeyFromPem(rPubFile, rPrivFile)
	fmt.Printf("RSA KEY: %v", rPrivKey)
}
```

## Testing Keys
The keys included under test are valid but not in use. They are used for test code only.