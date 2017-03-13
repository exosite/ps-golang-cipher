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
	// Note that we're passing 1, so that we'll log where the error happened,
	// rather than 0, which would log this function's file and line.
	pc, fn, line, _ := runtime.Caller(1)
	fcn := runtime.FuncForPC(pc).Name()

	if err == nil {
		err = fmt.Errorf("nil")
	}

	// MAYBE/2016-10-14: Is this TMI for production? [lb] wondering if we
	//                   should not send fcn name and line number to client.
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
	return &Cipher {}
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

		secretKey, _ := hex.DecodeString(secretKey_)

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

	plaintextBytes := []byte(plaintext)

	cfb := cipher.NewCFBEncrypter(ciph.cipherBlock, newInitVector)
	ciphertext := make([]byte, len(plaintextBytes))
	cfb.XORKeyStream(ciphertext, plaintextBytes)

	return ciphertext, newInitVector, nil
}

func (ciph *Cipher) CFBDecrypt(ciphertext []byte, publicInitVector []byte) (string, error) {
	if ciph.cipherBlock == nil {
		return ``, NewCipherAPIError(fmt.Errorf(`Cipher not prepared`))
	}

	cfbdec := cipher.NewCFBDecrypter(ciph.cipherBlock, publicInitVector)

	plaintextCopy := make([]byte, len(ciphertext))
	cfbdec.XORKeyStream(plaintextCopy, ciphertext)

	plaintextString := string(plaintextCopy)

	return plaintextString, nil
}

