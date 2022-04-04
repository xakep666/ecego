package ecego_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mathRand "math/rand"
	"testing"
	"time"

	"github.com/xakep666/ecego"
)

func TestExamples(t *testing.T) {
	// Based on examples from RFC8188
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Private key generate failed: %v", err)
		return
	}

	engine := ecego.NewEngine(ecego.SingleKey(privateKey))

	type testCase struct {
		ecego.OperationalParams

		plainText  []byte
		cipherText []byte
	}

	f := func(tc testCase) {
		t.Helper()

		actualPlainText, err := engine.Decrypt(tc.cipherText, nil, tc.OperationalParams)
		if err != nil {
			t.Errorf("decrypt failed: %v", err)
			return
		}

		actualCipherText, err := engine.Encrypt(tc.plainText, nil, tc.OperationalParams)

		if err != nil {
			t.Errorf("encrypt failed: %v", err)
			return
		}

		if !bytes.Equal(tc.plainText, actualPlainText) {
			t.Errorf("Plaintexts are different: expected \n%s, actual \n%s", tc.plainText, actualPlainText)
			return
		}

		if !bytes.Equal(tc.cipherText, actualCipherText) {
			t.Errorf("Ciphertexts are different: expected \n%v, actual \n%v", tc.cipherText, actualCipherText)
			return
		}
	}

	f(testCase{
		OperationalParams: ecego.OperationalParams{
			Version:    ecego.AES128GCM,
			StaticKey:  []byte{0xca, 0xa7, 0x65, 0x67, 0xeb, 0x58, 0x7a, 0x67, 0xe8, 0x81, 0x29, 0xaf, 0xed, 0x6b, 0x39, 0x3d},
			Salt:       []byte{0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b},
			RecordSize: 4096,
		},
		plainText: []byte("I am the walrus"),
		cipherText: []byte{0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b,
			0x0, 0x0, 0x10, 0x0, 0x0, 0xf8, 0xd0, 0x15, 0xb9, 0xbd, 0xaa, 0x16, 0x0, 0x44, 0xb9, 0x2, 0x91, 0x6a, 0x9a,
			0x19, 0xbb, 0xe2, 0x31, 0x90, 0x8b, 0xda, 0xdc, 0xc1, 0x1, 0xd4, 0xf0, 0xfe, 0x97, 0x2f, 0x13, 0x86, 0x38},
	})
	f(testCase{
		OperationalParams: ecego.OperationalParams{
			Version:    ecego.AES128GCM,
			StaticKey:  []byte{0x4, 0xed, 0xd9, 0x54, 0xfc, 0x54, 0x96, 0x72, 0xce, 0x45, 0xb5, 0x46, 0x32, 0x96, 0xd3, 0xd5},
			Salt:       []byte{0xb8, 0xd0, 0xa4, 0x5a, 0x23, 0x58, 0xcc, 0xa4, 0xe7, 0x4, 0xdf, 0x63, 0x8b, 0x7f, 0xaa, 0x58},
			RecordSize: 25,
			KeyID:      []byte("a1"),
			Pad:        1,
		},
		plainText: []byte("I am the walrus"),
		cipherText: []byte{0xb8, 0xd0, 0xa4, 0x5a, 0x23, 0x58, 0xcc, 0xa4, 0xe7, 0x4, 0xdf, 0x63, 0x8b, 0x7f, 0xaa, 0x58,
			0x0, 0x0, 0x0, 0x19, 0x2, 0x61, 0x31, 0xce, 0x1b, 0xc7, 0x21, 0xcf, 0xf8, 0x27, 0xbe, 0x3, 0xaa, 0x74, 0x66,
			0x28, 0xbf, 0x1c, 0xa3, 0xba, 0xa4, 0x72, 0x24, 0x58, 0xc4, 0xf, 0x2a, 0x5, 0xd4, 0x5b, 0xe4, 0x8f, 0xa8,
			0x50, 0x3d, 0xd3, 0xc7, 0x23, 0x9d, 0x4e, 0x11, 0x42, 0x84, 0xa6, 0xc, 0xf7, 0x4a, 0xc2, 0xd6, 0x22, 0xa4,
			0xbf, 0xb8},
	})
}

func fillDefaultRecordSize(input []byte, encryptParams, decryptParams *ecego.OperationalParams) {
	if encryptParams.RecordSize != 0 {
		return
	}

	encryptParams.RecordSize = uint32(len(input)) + 1
	switch encryptParams.Version {
	case ecego.AESGCM128:
		encryptParams.RecordSize += 1
	case ecego.AESGCM:
		encryptParams.RecordSize += 2
	default:
		encryptParams.RecordSize += 23
	}

	if decryptParams.Version == ecego.AES128GCM {
		decryptParams.RecordSize = 0
	} else if decryptParams.RecordSize == 0 {
		decryptParams.RecordSize = encryptParams.RecordSize
	}
}

func encryptDecrypt(t *testing.T, engineEncrypt, engineDecrypt *ecego.Engine, encryptParams, decryptParams ecego.OperationalParams, input []byte) {
	t.Helper()
	fillDefaultRecordSize(input, &encryptParams, &decryptParams)

	if encryptParams.Salt == nil {
		encryptParams.Salt = make([]byte, ecego.KeySize)
		_, err := io.ReadFull(rand.Reader, encryptParams.Salt)
		if err != nil {
			t.Errorf("Salt read failed: %v", err)
			return
		}

		t.Logf("Salt read: %s", hex.EncodeToString(encryptParams.Salt))
	}
	decryptParams.Salt = encryptParams.Salt

	cipherText, err := engineEncrypt.Encrypt(input, nil, encryptParams)
	if err != nil {
		t.Errorf("encrypt failed: %v", err)
		return
	}

	plainText, err := engineDecrypt.Decrypt(cipherText, nil, decryptParams)
	if err != nil {
		t.Errorf("decrypt failed: %v", err)
		return
	}

	if !bytes.Equal(input, plainText) {
		t.Errorf("Plaintexts are different: expected \n%s, actual \n%s", input, plainText)
		return
	}
}

func generateInput(t *testing.T) []byte {
	t.Helper()

	mathRand.Seed(time.Now().UnixNano())

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	length := mathRand.Intn(100) + 1
	input := make([]byte, length)
	for i := 0; i < length; i++ {
		input[i] = alphabet[mathRand.Intn(len(alphabet))]
	}

	t.Logf("Generated input (len %d): %s", length, input)

	return input
}

func generateKey(t *testing.T) []byte {
	t.Helper()

	key := make([]byte, ecego.KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
		return nil
	}

	t.Logf("Generated key: %s", hex.EncodeToString(key))
	return key
}

func TestWithStaticKey(t *testing.T) {
	input := generateInput(t)
	key := generateKey(t)

	f := func(version ecego.Version) {
		t.Helper()

		params := ecego.OperationalParams{
			Version:   version,
			StaticKey: key,
		}

		engine := ecego.NewEngine(nil)

		encryptDecrypt(t, engine, engine, params, params, input)
	}

	f(ecego.AES128GCM)
	f(ecego.AESGCM128)
	f(ecego.AESGCM)
}

func TestExactlyOneRecord(t *testing.T) {
	input := generateInput(t)
	key := generateKey(t)

	f := func(version ecego.Version) {
		t.Helper()

		params := ecego.OperationalParams{
			Version:    version,
			StaticKey:  key,
			RecordSize: uint32(len(input)) + 100,
		}

		engine := ecego.NewEngine(nil)

		encryptDecrypt(t, engine, engine, params, params, input)
	}

	f(ecego.AES128GCM)
	f(ecego.AESGCM128)
	f(ecego.AESGCM)
}

func TestWithAuthSecret(t *testing.T) {
	input := generateInput(t)
	key := generateKey(t)
	authSecret := generateKey(t)

	f := func(version ecego.Version) {
		t.Helper()

		params := ecego.OperationalParams{
			Version:   version,
			StaticKey: key,
		}

		engine := ecego.NewEngine(nil, ecego.WithAuthSecret(authSecret))

		encryptDecrypt(t, engine, engine, params, params, input)
	}

	f(ecego.AES128GCM)
	f(ecego.AESGCM128)
	f(ecego.AESGCM)
}

func TestTooMuchPadding(t *testing.T) {
	// The earlier versions had a limit to how much padding they could include in
	// each record, which means that they could fail to encrypt if too much padding
	// was requested with a large record size.

	input := []byte{'x'}
	key := generateKey(t)
	salt := generateKey(t)

	f := func(version ecego.Version) {
		t.Helper()

		padSize := uint32(version.PaddingSize())
		recordSize := 1<<(8*padSize) + padSize + 1
		params := ecego.OperationalParams{
			Version:    version,
			StaticKey:  key,
			Salt:       salt,
			RecordSize: recordSize,
			Pad:        recordSize,
		}

		_, err := ecego.NewEngine(nil).Encrypt(input, nil, params)
		if err == nil {
			t.Errorf("Encryption succeeded, but should not have")
			return
		}

		t.Logf("Error returned: %v", err)
	}

	f(ecego.AESGCM128)
	f(ecego.AESGCM)
}

func TestDetectTruncation(t *testing.T) {
	input := []byte{'x', 'y'}
	key := generateKey(t)
	salt := generateKey(t)

	f := func(version ecego.Version) {
		t.Helper()

		params := ecego.OperationalParams{
			Version:   version,
			StaticKey: key,
			Salt:      salt,
		}

		engine := ecego.NewEngine(nil)

		encrypted, err := engine.Encrypt(input, nil, params)
		if err != nil {
			t.Errorf("Encryption failed: %v", err)
			return
		}

		_, err = engine.Decrypt(encrypted[:5], nil, params)
		if err == nil {
			t.Errorf("Decryption succeeded, but should not have")
			return
		}

		t.Logf("Error returned: %v", err)
	}

	f(ecego.AES128GCM)
	f(ecego.AESGCM128)
	f(ecego.AESGCM)
}

func TestDH(t *testing.T) {
	// the static key is used by receiver
	staticKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Receiver private key generate failed: %v", err)
		return
	}

	t.Logf("Receiver private key: X: %s, Y: %s, D: %s", staticKey.X, staticKey.Y, staticKey.D)

	// the ephemeral key is used by the sender
	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Receiver private key generate failed: %v", err)
		return
	}

	t.Logf("Sender private key: X: %s, Y: %s, D: %s", ephemeralKey.X, ephemeralKey.Y, ephemeralKey.D)

	input := generateInput(t)
	authSecret := generateKey(t)
	salt := generateKey(t)

	f := func(version ecego.Version) {
		t.Helper()

		encryptDecrypt(t,
			ecego.NewEngine(ecego.SingleKey(staticKey), ecego.WithAuthSecret(authSecret), ecego.WithKeyLabel("test")),
			ecego.NewEngine(ecego.SingleKey(ephemeralKey), ecego.WithAuthSecret(authSecret), ecego.WithKeyLabel("test")),
			ecego.OperationalParams{
				Version: version,
				Salt:    salt,
				DH:      elliptic.Marshal(ephemeralKey.Curve, ephemeralKey.X, ephemeralKey.Y),
			},
			ecego.OperationalParams{
				Version: version,
				Salt:    salt,
				DH:      elliptic.Marshal(staticKey.Curve, staticKey.X, staticKey.Y),
			},
			input,
		)
	}

	f(ecego.AES128GCM)
	f(ecego.AESGCM128)
	f(ecego.AESGCM)
}

func TestErrorsDecrypt(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Private key generate failed: %v", err)
		return
	}

	f := func(input []byte, params ecego.OperationalParams, errExpected error) {
		t.Helper()

		_, err := ecego.NewEngine(ecego.SingleKey(privateKey)).Decrypt(input, nil, params)
		if !errors.Is(err, errExpected) {
			t.Errorf("Error %v is not an %v", err, errExpected)
			return
		}
	}

	f(
		[]byte{0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6},
		ecego.OperationalParams{
			Salt: generateKey(t),
		},
		ecego.ErrTruncated,
	)
	f(
		[]byte{
			0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b, 0x0, 0x0,
			0x10, 0x0, 0x0, 0xf8, 0xd0, 0x15, 0xb9, 0xbd, 0xaa, 0x16, 0x0, 0x44, 0xb9, 0x2, 0x91, 0x6a, 0x9a, 0x19,
			0xbb, 0xe2, 0x31, 0x90, 0x8b, 0xda, 0xdc, 0xc1, 0x1, 0xd4, 0xf0, 0xfe, 0x97, 0x2f, 0x13, 0x86, 0x38,
		},
		ecego.OperationalParams{
			Salt:      generateKey(t),
			StaticKey: []byte{1, 2, 3, 4, 5, 6},
		},
		ecego.ErrInvalidKeySize,
	)
	f(
		[]byte{
			0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b, 0x0, 0x0,
			0x10, 0x0, 0x0, 0xf8, 0xd0, 0x15, 0xb9, 0xbd, 0xaa, 0x16, 0x0, 0x44, 0xb9, 0x2, 0x91, 0x6a, 0x9a, 0x19,
			0xbb, 0xe2, 0x31, 0x90, 0x8b, 0xda, 0xdc, 0xc1, 0x1, 0xd4, 0xf0, 0xfe, 0x97, 0x2f, 0x13, 0x86, 0x38,
		},
		ecego.OperationalParams{
			Version:   ecego.AESGCM,
			StaticKey: generateKey(t),
			DH:        elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y),
			Salt:      []byte{1, 2, 3, 4, 5, 6},
		},
		ecego.ErrInvalidSaltSize,
	)
	f(
		[]byte{
			0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b, 0x0, 0x0,
			0x10, 0x0, 0x0, 0xf8, 0xd0, 0x15, 0xb9, 0xbd, 0xaa, 0x16, 0x0, 0x44, 0xb9, 0x2, 0x91, 0x6a, 0x9a, 0x19,
			0xbb, 0xe2, 0x31, 0x90, 0x8b, 0xda, 0xdc, 0xc1, 0x1, 0xd4, 0xf0, 0xfe, 0x97, 0x2f, 0x13, 0x86, 0x38,
		},
		ecego.OperationalParams{
			Salt: generateKey(t),
			DH:   []byte{1, 2, 3, 4, 5},
		},
		ecego.ErrInvalidDH,
	)
	f(
		[]byte{
			0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b, 0x0, 0x0,
			0x10, 0x0, 0x0, 0xf8, 0xd0, 0x15, 0xb9, 0xbd, 0xaa, 0x16, 0x0, 0x44, 0xb9, 0x2, 0x91, 0x6a, 0x9a, 0x19,
			0xb8, 0x31, 0xad, 0x71, 0x87, 0x8b, 0x5b, 0x28, 0xaa, 0x8, 0xd6, 0x7b, 0xac, 0xa4, 0xb8, 0xf6, 0x27,
		},
		ecego.OperationalParams{
			StaticKey:  []byte{0xca, 0xa7, 0x65, 0x67, 0xeb, 0x58, 0x7a, 0x67, 0xe8, 0x81, 0x29, 0xaf, 0xed, 0x6b, 0x39, 0x3d},
			Salt:       []byte{0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b},
			DH:         elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y),
			RecordSize: 4096,
		},
		ecego.ErrInvalidPadding,
	)
}

func TestErrorMAC(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Private key generate failed: %v", err)
		return
	}

	_, err = ecego.NewEngine(ecego.SingleKey(privateKey)).Decrypt(
		[]byte{
			0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b, 0x0, 0x0,
			0x10, 0x0, 0x0, 0xf8, 0xd0, 0x15, 0xb9, 0xbd, 0xaa, 0x16, 0x0, 0x44, 0xb9, 0x2, 0x91, 0x6a, 0x9a, 0x19,
			0xb8, 0x31, 0xad, 0x71, 0x87, 0x8b, 0x5a, 0x28, 0xaa, 0x8, 0xd6, 0x7b, 0xac, 0xa4, 0xb8, 0xf6, 0x27,
		},
		nil,
		ecego.OperationalParams{
			StaticKey:  []byte{0xca, 0xa7, 0x65, 0x67, 0xeb, 0x58, 0x7a, 0x67, 0xe8, 0x81, 0x29, 0xaf, 0xed, 0x6b, 0x39, 0x3d},
			Salt:       []byte{0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d, 0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf6, 0x8c, 0x67, 0x9b},
			DH:         elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y),
			RecordSize: 4096,
		},
	)
	if errors.Unwrap(err) == fmt.Errorf("cipher: message authentication failed") {
		t.Errorf("Error %v is not an mac error", err)
		return
	}
}

func TestErrorsEncrypt(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Private key generate failed: %v", err)
		return
	}

	f := func(input []byte, params ecego.OperationalParams, errExpected error) {
		t.Helper()

		_, err := ecego.NewEngine(ecego.SingleKey(privateKey)).Encrypt(input, nil, params)
		if !errors.Is(err, errExpected) {
			t.Errorf("Error %v is not an %v", err, errExpected)
			return
		}
	}

	f(
		generateInput(t),
		ecego.OperationalParams{
			Salt:      generateKey(t),
			StaticKey: generateKey(t),
			KeyID:     bytes.Repeat([]byte{'z'}, 500),
		},
		ecego.ErrKeyIDTooLong,
	)
	f(
		generateInput(t),
		ecego.OperationalParams{
			Salt: generateKey(t),
			DH:   []byte{1, 2, 3, 4, 5},
		},
		ecego.ErrInvalidDH,
	)
	f(
		generateInput(t),
		ecego.OperationalParams{
			Salt:      []byte{1, 2, 3, 4, 5},
			StaticKey: generateKey(t),
		},
		ecego.ErrInvalidSaltSize,
	)
	f(
		generateInput(t),
		ecego.OperationalParams{
			Salt:      generateKey(t),
			StaticKey: []byte{1, 2, 3, 4, 5},
		},
		ecego.ErrInvalidKeySize,
	)
	f(
		generateInput(t),
		ecego.OperationalParams{
			Salt:       generateKey(t),
			StaticKey:  generateKey(t),
			RecordSize: 1,
		},
		ecego.ErrTooSmallRecordSize,
	)
}
