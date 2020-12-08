package hpkecompact

import (
	"crypto/aes"
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var hpkeVersion = [7]byte{'H', 'P', 'K', 'E', '-', '0', '6'}

// Mode - Mode
type Mode byte

const (
	// ModeBase - Base mode
	ModeBase Mode = 0x00
	// ModePsk - PSK mode
	ModePsk Mode = 0x01
	// ModeAuth - Auth mode
	ModeAuth Mode = 0x02
	// ModeAuthPsk - PSK Auth mode
	ModeAuthPsk Mode = 0x03
)

// KemID - KEM ID
type KemID uint16

const (
	// KemX25519HkdfSha256 - X25519 with HKDF-SHA256
	KemX25519HkdfSha256 KemID = 0x0020
)

// KdfID - KDF ID
type KdfID uint16

const (
	// KdfHkdfSha256 - HKDF-SHA256
	KdfHkdfSha256 KdfID = 0x0001
)

// AeadID - AEAD ID
type AeadID uint16

const (
	// AeadAes128Gcm - AES128-GCM
	AeadAes128Gcm AeadID = 0x0001
	// AeadAes256Gcm - AES256-GCM
	AeadAes256Gcm AeadID = 0x0002
	// AeadGeneric - Any unlisted AEAD
	AeadGeneric AeadID = 0xffff
)

// Suite - HPKE suite
type Suite struct {
	suiteIDContext [10]byte
	suiteIDKEM     [5]byte
	hash           func() hash.Hash
	// KeyBytes - Size of the AEAD key, in bytes
	KeyBytes     uint16
	nonceBytes   uint16
	kemHashBytes uint16
}

// NewSuite - Create a new suite from its components
func NewSuite(kemID KemID, kdfID KdfID, aeadID AeadID) (*Suite, error) {
	if kemID != KemX25519HkdfSha256 || kdfID != KdfHkdfSha256 {
		return nil, errors.New("unimplemented suite")
	}
	hash := sha256.New
	var keyBytes, nonceBytes uint16
	switch aeadID {
	case AeadAes128Gcm:
		keyBytes = 16
		nonceBytes = 12
	case AeadAes256Gcm:
		keyBytes = 32
		nonceBytes = 12
	case AeadGeneric:
		keyBytes = 0
		nonceBytes = 0
	default:
		return nil, errors.New("unimplemented suite")
	}
	var kemHashBytes uint16
	switch kemID {
	case KemX25519HkdfSha256:
		kemHashBytes = 32
	default:
		return nil, errors.New("unimplemented suite")
	}
	suite := Suite{
		suiteIDContext: getSuiteIDContext(kemID, kdfID, aeadID),
		suiteIDKEM:     getSuiteIDKEM(kemID),
		hash:           hash, KeyBytes: keyBytes,
		nonceBytes:   nonceBytes,
		kemHashBytes: kemHashBytes,
	}
	return &suite, nil
}

func getSuiteIDContext(kemID KemID, kdfID KdfID, aeadID AeadID) [10]byte {
	suiteIDContext := [10]byte{'H', 'P', 'K', 'E', 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(suiteIDContext[4:6], uint16(kemID))
	binary.BigEndian.PutUint16(suiteIDContext[6:8], uint16(kdfID))
	binary.BigEndian.PutUint16(suiteIDContext[8:10], uint16(aeadID))
	return suiteIDContext
}

func getSuiteIDKEM(kemID KemID) [5]byte {
	suiteIDKEM := [5]byte{'K', 'E', 'M', 0, 0}
	binary.BigEndian.PutUint16(suiteIDKEM[3:5], uint16(kemID))
	return suiteIDKEM
}

func (suite *Suite) labeledExtract(suiteID []byte, salt []byte, label string, ikm []byte) []byte {
	secret := hpkeVersion[:]
	secret = append(secret, suiteID...)
	secret = append(secret, []byte(label)...)
	secret = append(secret, ikm...)
	prk := hkdf.Extract(suite.hash, secret, salt)
	return prk
}

func (suite *Suite) labeledExpand(suiteID []byte, prk []byte, label string, info []byte, length uint16) ([]byte, error) {
	labeledInfo := []byte{0, 0}
	binary.BigEndian.PutUint16(labeledInfo, length)
	labeledInfo = append(labeledInfo, hpkeVersion[:]...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte(label)...)
	labeledInfo = append(labeledInfo, info...)
	reader := hkdf.Expand(suite.hash, prk, labeledInfo)
	out := make([]byte, length)
	if readNb, err := reader.Read(out); err != nil {
		return nil, err
	} else if readNb != int(length) {
		return nil, errors.New("unable to expand")
	}
	return out, nil
}

func verifyPskInputs(mode Mode, psk []byte, pskID []byte) error {
	if (len(psk) == 0) != (len(pskID) == 0) {
		return errors.New("a PSK and a PSK ID need both to be set")
	}
	if len(psk) > 0 {
		if mode == ModeBase || mode == ModeAuth {
			return errors.New("PSK input provided when not needed")
		}
	} else if mode == ModePsk || mode == ModeAuthPsk {
		return errors.New("PRK required for that mode")
	}
	return nil
}

// Context - An AEAD context
type Context struct {
	suite        *Suite
	SharedSecret []byte
	BaseNonce    []byte
	counter      []byte
}

func (suite *Suite) keySchedule(mode Mode, dhSecret []byte, info []byte, psk []byte, pskID []byte) (Context, error) {
	if err := verifyPskInputs(mode, psk, pskID); err != nil {
		return Context{}, err
	}
	pskIDHash := suite.labeledExtract(suite.suiteIDContext[:], nil, "psk_id_hash", pskID)
	infoHash := suite.labeledExtract(suite.suiteIDContext[:], nil, "info_hash", info)
	keyScheduleContext := []byte{byte(mode)}
	keyScheduleContext = append(keyScheduleContext, pskIDHash...)
	keyScheduleContext = append(keyScheduleContext, infoHash...)
	secret := suite.labeledExtract(suite.suiteIDContext[:], dhSecret, "secret", psk)
	sharedSecret, err := suite.labeledExpand(suite.suiteIDContext[:], secret, "key", keyScheduleContext, suite.KeyBytes)
	if err != nil {
		return Context{}, err
	}
	baseNonce, err := suite.labeledExpand(suite.suiteIDContext[:], secret, "base_nonce", keyScheduleContext, suite.nonceBytes)
	if err != nil {
		return Context{}, err
	}
	counter := make([]byte, suite.nonceBytes)
	for i := 0; i < len(counter); i++ {
		counter[i] = 0
	}
	return Context{
		suite:        suite,
		SharedSecret: sharedSecret,
		BaseNonce:    baseNonce,
		counter:      counter,
	}, nil
}

// GenerateKeyPair - Generate a random key pair
func (suite *Suite) GenerateKeyPair() ([]byte, []byte, error) {
	var pk, sk [32]byte
	if _, err := crypto_rand.Read(sk[:]); err != nil {
		return nil, nil, err
	}
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk[:], sk[:], nil
}

// DeterministicKeyPair - Derive a deterministic key pair from a seed
func (suite *Suite) DeterministicKeyPair(seed []byte) ([]byte, []byte, error) {
	var pk, sk [32]byte
	prk := suite.labeledExtract(suite.suiteIDKEM[:], nil, "dkp_prk", seed)
	xsk, err := suite.labeledExpand(suite.suiteIDKEM[:], prk, "sk", nil, 32)
	if err != nil {
		return nil, nil, err
	}
	copy(sk[:], xsk)

	curve25519.ScalarBaseMult(&pk, &sk)
	return pk[:], sk[:], nil
}

func (suite *Suite) dh(pk []byte, sk []byte) ([]byte, error) {
	dhSecret, err := curve25519.X25519(sk, pk)
	if err != nil {
		return nil, err
	}
	return dhSecret, nil
}

func (suite *Suite) extractAndExpandDH(dh []byte, kemContext []byte) ([]byte, error) {
	prk := suite.labeledExtract(suite.suiteIDKEM[:], nil, "eae_prk", dh)
	dhSecret, err := suite.labeledExpand(suite.suiteIDKEM[:], prk, "shared_secret", kemContext, suite.kemHashBytes)
	if err != nil {
		return nil, err
	}
	return dhSecret, nil
}

func (suite *Suite) encap(serverPk []byte, seed []byte) ([]byte, []byte, error) {
	var ephPk, ephSk []byte
	var err error
	if len(seed) > 0 {
		ephPk, ephSk, err = suite.DeterministicKeyPair(seed)
	} else {
		ephPk, ephSk, err = suite.GenerateKeyPair()
	}
	if err != nil {
		return nil, nil, err
	}
	dh, err := suite.dh(serverPk, ephSk)
	if err != nil {
		return nil, nil, err
	}
	kemContext := append(ephPk, serverPk...)
	dhSecret, err := suite.extractAndExpandDH(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return dhSecret, ephPk, nil
}

func (suite *Suite) decap(ephPk []byte, serverPk []byte, serverSk []byte) ([]byte, error) {
	dh, err := suite.dh(ephPk, serverSk)
	if err != nil {
		return nil, err
	}
	kemContext := append(ephPk, serverPk...)
	dhSecret, err := suite.extractAndExpandDH(dh, kemContext)
	if err != nil {
		return nil, err
	}
	return dhSecret, nil
}

// NewClientContext - Create a new context for a client (aka "sender")
func (suite *Suite) NewClientContext(serverPk []byte, info []byte) (Context, []byte, error) {
	dhSecret, enc, err := suite.encap(serverPk, nil)
	if err != nil {
		return Context{}, nil, err
	}
	context, err := suite.keySchedule(ModeBase, dhSecret, info, nil, nil)
	if err != nil {
		return Context{}, nil, err
	}
	return context, enc, nil
}

// NewClientDeterministicContext - Create a new deterministic context for a client - Should only be used for testing purposes
func (suite *Suite) NewClientDeterministicContext(serverPk []byte, info []byte, seed []byte) (Context, []byte, error) {
	dhSecret, enc, err := suite.encap(serverPk, seed)
	if err != nil {
		return Context{}, nil, err
	}
	context, err := suite.keySchedule(ModeBase, dhSecret, info, nil, nil)
	if err != nil {
		return Context{}, nil, err
	}
	return context, enc, nil
}

// NewServerContext - Create a new context for a server (aka "recipient")
func (suite *Suite) NewServerContext(enc []byte, serverPk []byte, serverSk []byte, info []byte) (Context, error) {
	dhSecret, err := suite.decap(enc, serverPk, serverSk)
	if err != nil {
		return Context{}, err
	}
	context, err := suite.keySchedule(ModeBase, dhSecret, info, nil, nil)
	if err != nil {
		return Context{}, err
	}
	return context, nil
}

func (context *Context) incrementCounter() error {
	carry := uint16(1)
	for i := len(context.counter); ; {
		i--
		x := uint16(context.counter[i]) + carry
		context.counter[i] = byte(x & 0xff)
		carry = x >> 8
		if i == 0 {
			break
		}
	}
	if carry != 0 {
		return errors.New("Overflow")
	}
	return nil
}

// NextNonce - Get the next nonce to encrypt/decrypt a message with an AEAD
func (context *Context) NextNonce() []byte {
	if len(context.counter) != len(context.BaseNonce) {
		panic("Inconsistent nonce length")
	}
	nonce := context.BaseNonce[:]
	for i := 0; i < len(nonce); i++ {
		nonce[i] ^= context.counter[i]
	}
	context.incrementCounter()
	return nonce
}

// Encrypt - Encrypt and authenticate a message, with optional associated data
func (context *Context) Encrypt(ad []byte, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(context.SharedSecret)
	if err != nil {
		return nil, err
	}
	nonce := context.NextNonce()
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, message, ad)
	return ciphertext, nil
}

// Decrypt - Verify and decrypt a ciphertext, with optional associated data
func (context *Context) Decrypt(ad []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(context.SharedSecret)
	if err != nil {
		return nil, err
	}
	nonce := context.NextNonce()
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	message, err := aesgcm.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	return message, nil
}
