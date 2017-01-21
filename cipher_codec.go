/**
 * \file cipher_codec.go
 */
package exocipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jmoiron/jsonq"
	"github.com/juju/loggo"

	"github.com/exosite/ps-golang-gopenshift"
	"github.com/exosite/ps-golang-logger"
)

var logger = loggo.GetLogger("exo.cipher")
func SetLogLevel() {
	exologger.SetLoggerLogLevel(&logger, nil)
}

type CipherAPI interface {
	PrepareCipher() (bool, error)
	CFBEncrypt(plaintext string) ([]byte, []byte, error)
	CFBDecrypt(ciphertext []byte, publicInitVector []byte) (string, error)
}

// *** Error object.

type CipherAPIError struct {
	Where string
	Err error
}

func NewCipherAPIError(err error) error {
	// notice that we're using 1, so it will actually log the where
	// the error happened, 0 = this function, we don't want that.
	pc, fn, line, _ := runtime.Caller(1)
	fcn := runtime.FuncForPC(pc).Name()

	if err == nil {
		err = fmt.Errorf("nil")
	}

	// MAYBE/2016-10-14: Is this TMI for production? [lb] wondering if we
	//                   shouldn't send fcn name and line number to client.
	return &CipherAPIError{
		Where: fmt.Sprintf("%s[%s:%d]", fcn, fn, line),
		Err: err,
	}
}

func (e *CipherAPIError) Error() string {
	return e.Err.Error()
}

// *** Cipher implementation.

type Cipher struct {
	cipherBlock cipher.Block
}

func NewCipher() *Cipher {
	//SetLogLevel()

	return &Cipher {
		//cipherBlock: ,
	}
}

func (ciph *Cipher) PrepareCipher() (bool, error) {
	if ciph.cipherBlock == nil {
		// MAYBE: Put the secret under /app/etc/secrets and use gopenshift.GetSecret.
		secretsDir, err := gopenshift.GetSaltySecretDir()
		if err != nil {
			logger.Warningf(`PrepareCipher: GetSaltySecretDir: %v / err: %+v`, secretsDir, err)
			err = errors.New("Missing salty-secret directory")
			return false, err
		}
		secretPath := filepath.Join(secretsDir, "salty-secret.json")
		secretContent, err := ioutil.ReadFile(secretPath)
		if err != nil {
			logger.Warningf(`ReadFile: %v / err: %+v`, secretPath, err)
			err = errors.New("Missing salty file")
			return false, err
		}
		logger.Tracef(`PrepareCipher: secretPath: %v`, secretPath)
		logger.Tracef(`PrepareCipher: secretContent: %+v`, secretContent)

		// Decode it into a map[string]interface{}:
		secret_json := map[string]interface{}{}
		decoder := json.NewDecoder(strings.NewReader(string(secretContent)))
		decoder.Decode(&secret_json)
		jq := jsonq.NewQuery(secret_json)

		secretKey_, err := jq.String("data", "salt")
		if err != nil {
			logger.Warningf(`ReadFile: %v / err: %+v`, secretPath, err)
			err = errors.New("Missing data salt")
			return false, err
		}
		logger.Tracef("DecodeString: secretKey_: %v\n", secretKey_)
		logger.Tracef("DecodeString: len(secretKey_): %v\n", len(secretKey_))

		secretKey, _ := hex.DecodeString(secretKey_)
		logger.Tracef("DecodeString: secretKey: %v\n", secretKey)
		logger.Tracef("DecodeString: len(secretKey): %v\n", len(secretKey))

		cipherBlock, err := aes.NewCipher(secretKey)
		ciph.cipherBlock = cipherBlock
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

// Cipher Feedback (CFB) mode.
func (ciph *Cipher) CFBEncrypt(plaintext string) ([]byte, []byte, error) {
	if ciph.cipherBlock == nil {
		return nil, nil, NewCipherAPIError(fmt.Errorf(`Cipher not prepared`))
	}

	// If the database is comprised, we can mitigate the risk of a rainbow
	// dictionary attack by using a unique initialization vector for each
	// piece of encoded information.
	// The initialization vector should be the size of the AES block.
	// The secret key is 32 characters -- which means aes.NewCipher
	// uses AES-128. So the block size is 128 bits, or 16 bytes.
	newInitVector := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, newInitVector); err != nil {
		return nil, nil, err
	}
	logger.Tracef(`CFBEncrypt: newInitVector: %v`, newInitVector)

	plaintextBytes := []byte(plaintext)

	cfb := cipher.NewCFBEncrypter(ciph.cipherBlock, newInitVector)
	ciphertext := make([]byte, len(plaintextBytes))
	cfb.XORKeyStream(ciphertext, plaintextBytes)

	logger.Tracef(`CFBEncrypt: %s => %v => %x`, plaintext, plaintextBytes, ciphertext)

	logger.Tracef(`CFBEncrypt: plaintext/v: %v`, plaintext)
	logger.Tracef(`CFBEncrypt: len(plaintext)/v: %v`, len(plaintext))

	logger.Tracef(`CFBEncrypt: plaintextBytes/v: %v`, plaintextBytes)
	logger.Tracef(`CFBEncrypt: len(plaintextBytes)/v: %v`, len(plaintextBytes))

	logger.Tracef(`CFBEncrypt: ciphertext/v: %v`, ciphertext)
	logger.Tracef(`CFBEncrypt: len(ciphertext)/v: %v`, len(ciphertext))

	logger.Tracef(`CFBEncrypt: ciphertext/+v: %+v`, ciphertext)
	logger.Tracef(`CFBEncrypt: len(ciphertext)/+v: %+v`, len(ciphertext))

	logger.Tracef(`CFBEncrypt: ciphertext/x: %x`, ciphertext)
	logger.Tracef(`CFBEncrypt: len(ciphertext)/x: %x`, len(ciphertext))

	return ciphertext, newInitVector, nil
}

func (ciph *Cipher) CFBDecrypt(ciphertext []byte, publicInitVector []byte) (string, error) {
	if ciph.cipherBlock == nil {
		return ``, NewCipherAPIError(fmt.Errorf(`Cipher not prepared`))
	}

	logger.Tracef(`CFBDecrypt: ciphertext/\%x: %x`, ciphertext)
	logger.Tracef(`CFBDecrypt: ciphertext/\%v: %v`, ciphertext)
	logger.Tracef(`CFBDecrypt: len(ciphertext): %v`, len(ciphertext))
	logger.Tracef(`CFBDecrypt: string(ciphertext): %s`, string(ciphertext))

	logger.Tracef(`CFBDecrypt: publicInitVector: %v`, publicInitVector)
	logger.Tracef(`CFBDecrypt: len(publicInitVector): %v`, len(publicInitVector))

	cfbdec := cipher.NewCFBDecrypter(ciph.cipherBlock, publicInitVector)

	logger.Tracef(`CFBDecrypt: len(ciphertext): %v`, len(ciphertext))
	plaintextCopy := make([]byte, len(ciphertext))
	cfbdec.XORKeyStream(plaintextCopy, ciphertext)

	fmt.Printf(`CFBDecrypt: %x => %s`, ciphertext, plaintextCopy)

	logger.Tracef(`CFBDecrypt: len(ciphertext): %v`, len(ciphertext))
	logger.Tracef(`CFBDecrypt: len(plaintextCopy): %v`, len(plaintextCopy))

	plaintextString := string(plaintextCopy)
	logger.Tracef(`CFBDecrypt: plaintextString: %v`, plaintextString)
	logger.Tracef(`CFBDecrypt: len(plaintextString): %v`, len(plaintextString))

	return plaintextString, nil
}

