// cipher_codec_test.go
// vim:tw=0:ts=4:sw=4:noet

package exocipher

// FIXME: [lb] needs to flesh this out.

import (
	"testing"
)

func TestCipherCodecAPIErrorNil(t *testing.T) {
	err := NewCipherAPIError(nil)
	if err == nil {
		t.Errorf("NewCipherAPIError returned nil, but should not")
	}
	// Going for all the coverage!
	_ = err.Error()
}

func TestCipherCodecEncryptWithoutPrepareCipher(t *testing.T) {
	cipher := NewCipher()
	fakeToken := "XXX"
	_, _, err := cipher.CFBEncrypt(fakeToken)
	if err == nil {
		t.Errorf("CFGEncrypt did not return err, but should")
	}
}

func TestCipherCodecDecryptWithoutPrepareCipher(t *testing.T) {
	cipher := NewCipher()
	fakeTokenBlob := "XXX"
	fakeInitvBlob := "XXX"
	_, err := cipher.CFBDecrypt([]byte(fakeTokenBlob), []byte(fakeInitvBlob),)
	if err == nil {
		t.Errorf("CFBDecrypt did not return err, but should")
	}
}

func TestCipherCodecEncryptThenDecrypt(t *testing.T) {
	cipher := NewCipher()
	cipher.PrepareCipher()
	content := "This is my secret"
	encoded, initVec, err := cipher.CFBEncrypt(content)
	if err != nil {
		t.Errorf("CFBEncrypt returned an err: %v", err)
	}
	_, err = cipher.CFBDecrypt([]byte(encoded), []byte(initVec),)
	if err != nil {
		t.Errorf("CFBDecrypt returned an err: %v", err)
	}
}

