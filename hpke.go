package hpkecompact

import (
	"crypto/aes"
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var hpkeVersion = [7]byte{'H', 'P', 'K', 'E', '-', '0', '7'}

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
	// AeadChaCha20Poly1305 - ChaCha20-Poly1305
	AeadChaCha20Poly1305 AeadID = 0x0003
	// AeadGeneric - Any unlisted AEAD
	AeadGeneric AeadID = 0xffff
)

// Psk - Pre-shared key and key ID
type Psk struct {
	Key []byte
	ID  []byte
}

// KeyPair - A key pair (packed as a byte string)
type KeyPair struct {
	// PublicKey - Public key
	PublicKey []byte
	// SecretKey - Secret key
	SecretKey []byte
}

// Suite - HPKE suite
type Suite struct {
	suiteIDContext [10]byte
	suiteIDKEM     [5]byte
	hash           func() hash.Hash
	prkBytes       uint16
	// KeyBytes - Size of the AEAD key, in bytes
	KeyBytes     uint16
	nonceBytes   uint16
	kemHashBytes uint16
	aeadID       AeadID
}

// NewSuite - Create a new suite from its components
func NewSuite(kemID KemID, kdfID KdfID, aeadID AeadID) (*Suite, error) {
	if kemID != KemX25519HkdfSha256 || kdfID != KdfHkdfSha256 {
		return nil, errors.New("unimplemented suite")
	}
	hash := sha256.New
	nonceBytes := uint16(12)
	var keyBytes uint16
	switch aeadID {
	case AeadAes128Gcm:
		keyBytes = 16
	case AeadAes256Gcm:
		keyBytes = 32
	case AeadChaCha20Poly1305:
		keyBytes = 32
	case AeadGeneric:
		keyBytes = 0
		nonceBytes = 0
	default:
		return nil, errors.New("unimplemented suite")
	}
	var prkBytes uint16
	switch kdfID {
	case KdfHkdfSha256:
		prkBytes = 32
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
		hash:           hash,
		KeyBytes:       keyBytes,
		prkBytes:       prkBytes,
		nonceBytes:     nonceBytes,
		kemHashBytes:   kemHashBytes,
		aeadID:         aeadID,
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

// Extract - KDF-Extract
func (suite *Suite) Extract(secret []byte, salt []byte) []byte {
	return hkdf.Extract(suite.hash, secret, salt)
}

// Expand - KDF-Expand
func (suite *Suite) Expand(prk []byte, info []byte, length uint16) ([]byte, error) {
	reader := hkdf.Expand(suite.hash, prk, info)
	out := make([]byte, length)
	if readNb, err := reader.Read(out); err != nil {
		return nil, err
	} else if readNb != int(length) {
		return nil, errors.New("unable to expand")
	}
	return out, nil
}

func (suite *Suite) labeledExtract(suiteID []byte, salt []byte, label string, ikm []byte) []byte {
	secret := append(hpkeVersion[:], suiteID...)
	secret = append(secret, []byte(label)...)
	secret = append(secret, ikm...)
	return suite.Extract(secret, salt)
}

func (suite *Suite) labeledExpand(suiteID []byte, prk []byte, label string, info []byte, length uint16) ([]byte, error) {
	labeledInfo := []byte{0, 0}
	binary.BigEndian.PutUint16(labeledInfo, length)
	labeledInfo = append(labeledInfo, hpkeVersion[:]...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte(label)...)
	labeledInfo = append(labeledInfo, info...)
	return suite.Expand(prk, labeledInfo, length)
}

func verifyPskInputs(mode Mode, psk *Psk) error {
	if psk != nil && ((len(psk.Key) == 0) != (len(psk.ID) == 0)) {
		return errors.New("a PSK and a PSK ID need both to be set")
	}
	if psk != nil {
		if mode == ModeBase || mode == ModeAuth {
			return errors.New("PSK input provided when not needed")
		}
	} else if mode == ModePsk || mode == ModeAuthPsk {
		return errors.New("PRK required for that mode")
	}
	return nil
}

// innerContext - An AEAD context
type innerContext struct {
	suite          *Suite
	aead           aeadImpl
	sharedSecret   []byte
	exporterSecret []byte
	baseNonce      []byte
	counter        []byte
}

// ClientContext - A client encryption context
type ClientContext struct {
	inner innerContext
}

// ServerContext - A server encryption context
type ServerContext struct {
	inner innerContext
}

func (suite *Suite) keySchedule(isSender bool, mode Mode, dhSecret []byte, info []byte, psk *Psk) (innerContext, error) {
	if err := verifyPskInputs(mode, psk); err != nil {
		return innerContext{}, err
	}
	if psk == nil {
		psk = &Psk{}
	}
	pskIDHash := suite.labeledExtract(suite.suiteIDContext[:], nil, "psk_id_hash", psk.ID)
	infoHash := suite.labeledExtract(suite.suiteIDContext[:], nil, "info_hash", info)
	keyScheduleContext := []byte{byte(mode)}
	keyScheduleContext = append(keyScheduleContext, pskIDHash...)
	keyScheduleContext = append(keyScheduleContext, infoHash...)
	secret := suite.labeledExtract(suite.suiteIDContext[:], dhSecret, "secret", psk.Key)
	sharedSecret, err := suite.labeledExpand(suite.suiteIDContext[:], secret, "key", keyScheduleContext, suite.KeyBytes)
	if err != nil {
		return innerContext{}, err
	}
	exporterSecret, err := suite.labeledExpand(suite.suiteIDContext[:], secret, "exp", keyScheduleContext, suite.prkBytes)
	if err != nil {
		return innerContext{}, err
	}
	baseNonce, err := suite.labeledExpand(suite.suiteIDContext[:], secret, "base_nonce", keyScheduleContext, suite.nonceBytes)
	if err != nil {
		return innerContext{}, err
	}
	counter := make([]byte, suite.nonceBytes)
	var aead aeadImpl
	switch suite.aeadID {
	case AeadAes128Gcm, AeadAes256Gcm:
		aead, err = newAesAead(sharedSecret)
	case AeadChaCha20Poly1305:
		aead, err = newChaChaPolyAead(sharedSecret)
	default:
		return innerContext{}, errors.New("unimplemented AEAD")
	}
	if err != nil {
		return innerContext{}, err
	}
	return innerContext{
		suite:          suite,
		aead:           aead,
		sharedSecret:   sharedSecret,
		exporterSecret: exporterSecret,
		baseNonce:      baseNonce,
		counter:        counter,
	}, nil
}

// GenerateKeyPair - Generate a random key pair
func (suite *Suite) GenerateKeyPair() (KeyPair, error) {
	var pk, sk [32]byte
	if _, err := crypto_rand.Read(sk[:]); err != nil {
		return KeyPair{}, err
	}
	curve25519.ScalarBaseMult(&pk, &sk)
	return KeyPair{PublicKey: pk[:], SecretKey: sk[:]}, nil
}

// DeterministicKeyPair - Derive a deterministic key pair from a seed
func (suite *Suite) DeterministicKeyPair(seed []byte) (KeyPair, error) {
	var pk, sk [32]byte
	prk := suite.labeledExtract(suite.suiteIDKEM[:], nil, "dkp_prk", seed)
	xsk, err := suite.labeledExpand(suite.suiteIDKEM[:], prk, "sk", nil, 32)
	if err != nil {
		return KeyPair{}, err
	}
	copy(sk[:], xsk)
	curve25519.ScalarBaseMult(&pk, &sk)
	return KeyPair{PublicKey: pk[:], SecretKey: sk[:]}, nil
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
	var ephKp KeyPair
	var err error
	if len(seed) > 0 {
		ephKp, err = suite.DeterministicKeyPair(seed)
	} else {
		ephKp, err = suite.GenerateKeyPair()
	}
	if err != nil {
		return nil, nil, err
	}
	dh, err := suite.dh(serverPk, ephKp.SecretKey)
	if err != nil {
		return nil, nil, err
	}
	kemContext := append(ephKp.PublicKey, serverPk...)
	dhSecret, err := suite.extractAndExpandDH(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return dhSecret, ephKp.PublicKey, nil
}

func (suite *Suite) decap(ephPk []byte, serverKp KeyPair) ([]byte, error) {
	dh, err := suite.dh(ephPk, serverKp.SecretKey)
	if err != nil {
		return nil, err
	}
	kemContext := append(ephPk, serverKp.PublicKey...)
	dhSecret, err := suite.extractAndExpandDH(dh, kemContext)
	if err != nil {
		return nil, err
	}
	return dhSecret, nil
}

func (suite *Suite) authEncap(serverPk []byte, clientKp KeyPair, seed []byte) ([]byte, []byte, error) {
	var ephKp KeyPair
	var err error
	if len(seed) > 0 {
		ephKp, err = suite.DeterministicKeyPair(seed)
	} else {
		ephKp, err = suite.GenerateKeyPair()
	}
	if err != nil {
		return nil, nil, err
	}
	dh1, err := suite.dh(serverPk, ephKp.SecretKey)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := suite.dh(serverPk, clientKp.SecretKey)
	if err != nil {
		return nil, nil, err
	}
	dh := append(dh1, dh2...)
	kemContext := append(ephKp.PublicKey, serverPk...)
	kemContext = append(kemContext, clientKp.PublicKey...)
	dhSecret, err := suite.extractAndExpandDH(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return dhSecret, ephKp.PublicKey, nil
}

func (suite *Suite) authDecap(ephPk []byte, serverKp KeyPair, clientPk []byte) ([]byte, error) {
	dh1, err := suite.dh(ephPk, serverKp.SecretKey)
	if err != nil {
		return nil, err
	}
	dh2, err := suite.dh(clientPk, serverKp.SecretKey)
	if err != nil {
		return nil, err
	}
	dh := append(dh1, dh2...)
	kemContext := append(ephPk, serverKp.PublicKey...)
	kemContext = append(kemContext, clientPk...)
	dhSecret, err := suite.extractAndExpandDH(dh, kemContext)
	if err != nil {
		return nil, err
	}
	return dhSecret, nil
}

// NewClientContext - Create a new context for a client (aka "sender")
func (suite *Suite) NewClientContext(serverPk []byte, info []byte, psk *Psk) (ClientContext, []byte, error) {
	dhSecret, enc, err := suite.encap(serverPk, nil)
	if err != nil {
		return ClientContext{}, nil, err
	}
	mode := ModeBase
	if psk != nil {
		mode = ModePsk
	}
	context, err := suite.keySchedule(true, mode, dhSecret, info, psk)
	if err != nil {
		return ClientContext{}, nil, err
	}
	return ClientContext{inner: context}, enc, nil
}

// NewClientDeterministicContext - Create a new deterministic context for a client - Should only be used for testing purposes
func (suite *Suite) NewClientDeterministicContext(serverPk []byte, info []byte, psk *Psk, seed []byte) (ClientContext, []byte, error) {
	dhSecret, enc, err := suite.encap(serverPk, seed)
	if err != nil {
		return ClientContext{}, nil, err
	}
	mode := ModeBase
	if psk != nil {
		mode = ModePsk
	}
	context, err := suite.keySchedule(true, mode, dhSecret, info, psk)
	if err != nil {
		return ClientContext{}, nil, err
	}
	return ClientContext{inner: context}, enc, nil
}

// NewServerContext - Create a new context for a server (aka "recipient")
func (suite *Suite) NewServerContext(enc []byte, serverKp KeyPair, info []byte, psk *Psk) (ServerContext, error) {
	dhSecret, err := suite.decap(enc, serverKp)
	if err != nil {
		return ServerContext{}, err
	}
	mode := ModeBase
	if psk != nil {
		mode = ModePsk
	}
	context, err := suite.keySchedule(false, mode, dhSecret, info, psk)
	if err != nil {
		return ServerContext{}, err
	}
	return ServerContext{inner: context}, nil
}

// NewAuthenticatedClientContext - Create a new context for a client (aka "sender"), with authentication
func (suite *Suite) NewAuthenticatedClientContext(clientKp KeyPair, serverPk []byte, info []byte, psk *Psk) (ClientContext, []byte, error) {
	dhSecret, enc, err := suite.authEncap(serverPk, clientKp, nil)
	if err != nil {
		return ClientContext{}, nil, err
	}
	mode := ModeAuth
	if psk != nil {
		mode = ModeAuthPsk
	}
	context, err := suite.keySchedule(true, mode, dhSecret, info, psk)
	if err != nil {
		return ClientContext{}, nil, err
	}
	return ClientContext{inner: context}, enc, nil
}

// NewAuthenticatedClientDeterministicContext - Create a new deterministic context for a client, with authentication - Should only be used for testing purposes
func (suite *Suite) NewAuthenticatedClientDeterministicContext(clientKp KeyPair, serverPk []byte, info []byte, psk *Psk, seed []byte) (ClientContext, []byte, error) {
	dhSecret, enc, err := suite.authEncap(serverPk, clientKp, seed)
	if err != nil {
		return ClientContext{}, nil, err
	}
	mode := ModeAuth
	if psk != nil {
		mode = ModeAuthPsk
	}
	context, err := suite.keySchedule(true, mode, dhSecret, info, psk)
	if err != nil {
		return ClientContext{}, nil, err
	}
	return ClientContext{inner: context}, enc, nil
}

// NewAuthenticatedServerContext - Create a new context for a server (aka "recipient"), with authentication
func (suite *Suite) NewAuthenticatedServerContext(clientPk []byte, enc []byte, serverKp KeyPair, info []byte, psk *Psk) (ServerContext, error) {
	dhSecret, err := suite.authDecap(enc, serverKp, clientPk)
	if err != nil {
		return ServerContext{}, err
	}
	mode := ModeAuth
	if psk != nil {
		mode = ModeAuthPsk
	}
	context, err := suite.keySchedule(false, mode, dhSecret, info, psk)
	if err != nil {
		return ServerContext{}, err
	}
	return ServerContext{inner: context}, nil
}

func (context *innerContext) incrementCounter() error {
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
// Note: this is not thread-safe.
func (context *innerContext) NextNonce() []byte {
	if len(context.counter) != len(context.baseNonce) {
		panic("Inconsistent nonce length")
	}
	nonce := make([]uint8, len(context.baseNonce))
	copy(nonce, context.baseNonce)
	for i := 0; i < len(nonce); i++ {
		nonce[i] ^= context.counter[i]
	}
	context.incrementCounter()
	return nonce
}

// EncryptToServer - Encrypt and authenticate a message for the server, with optional associated data
func (context *ClientContext) EncryptToServer(message []byte, ad []byte) ([]byte, error) {
	nonce := context.inner.NextNonce()
	return context.inner.aead.internal().Seal(nil, nonce, message, ad), nil
}

// DecryptFromClient - Verify and decrypt a ciphertext received from the client, with optional associated data
func (context *ServerContext) DecryptFromClient(ciphertext []byte, ad []byte) ([]byte, error) {
	nonce := context.inner.NextNonce()
	return context.inner.aead.internal().Open(nil, nonce, ciphertext, ad)
}

// ExporterSecret - Return the exporter secret
func (context *ClientContext) ExporterSecret() []byte {
	return context.inner.exporterSecret
}

// ExporterSecret - Return the exporter secret
func (context *ServerContext) ExporterSecret() []byte {
	return context.inner.exporterSecret
}

type aeadImpl interface {
	internal() cipher.AEAD
}

type aeadAesImpl struct {
	impl cipher.AEAD
}

func newAesAead(key []byte) (aeadAesImpl, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return aeadAesImpl{}, nil
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return aeadAesImpl{}, nil
	}
	aead := aeadAesImpl{impl: aesGcm}
	return aead, nil
}

func (aead aeadAesImpl) internal() cipher.AEAD {
	return aead.impl
}

type aeadChaChaPolyImpl struct {
	impl cipher.AEAD
}

func newChaChaPolyAead(key []byte) (aeadChaChaPolyImpl, error) {
	impl, err := chacha20poly1305.New(key)
	if err != nil {
		return aeadChaChaPolyImpl{}, nil
	}
	aead := aeadChaChaPolyImpl{impl: impl}
	return aead, nil
}

func (aead aeadChaChaPolyImpl) internal() cipher.AEAD {
	return aead.impl
}
