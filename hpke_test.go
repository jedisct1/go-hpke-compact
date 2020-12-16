package hpkecompact

import (
	"encoding/hex"
	"testing"

	"github.com/powerman/check"
)

func TestMain(m *testing.M) {
	check.TestMain(m)
}

func TestExchange(t *testing.T) {
	suite, err := NewSuite(KemX25519HkdfSha256, KdfHkdfSha256, AeadAes128Gcm)
	if err != nil {
		t.Fatal(err)
	}

	serverKp, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	clientCtx, encryptedSharedSecret, err := suite.NewClientContext(serverKp.PublicKey, []byte("test"), nil)
	if err != nil {
		t.Fatal(err)
	}

	serverCtx, err := suite.NewServerContext(encryptedSharedSecret, serverKp, []byte("test"), nil)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := clientCtx.EncryptToServer([]byte("message"), nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := serverCtx.DecryptFromClient(ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != "message" {
		t.Fatal("Unexpected decryption result")
	}

	ciphertext, err = serverCtx.EncryptToClient([]byte("response"), nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = clientCtx.DecryptFromServer(ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != "response" {
		t.Fatal("Unexpected decryption result")
	}
}

func TestAuthenticatedExchange(t *testing.T) {
	suite, err := NewSuite(KemX25519HkdfSha256, KdfHkdfSha256, AeadChaCha20Poly1305)
	if err != nil {
		t.Fatal(err)
	}

	clientKp, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	serverKp, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	psk := &Psk{ID: []byte("PSK ID"), Key: []byte("PSK key")}

	clientCtx, encryptedSharedSecret, err := suite.NewAuthenticatedClientContext(clientKp, serverKp.PublicKey, []byte("test"), psk)
	if err != nil {
		t.Fatal(err)
	}

	serverCtx, err := suite.NewAuthenticatedServerContext(clientKp.PublicKey, encryptedSharedSecret, serverKp, []byte("test"), psk)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := clientCtx.EncryptToServer([]byte("message"), nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := serverCtx.DecryptFromClient(ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != "message" {
		t.Fatal("Unexpected decryption result")
	}
}

func TestVectors(t *testing.T) {
	ctx, err := NewSuite(KemX25519HkdfSha256, KdfHkdfSha256, AeadAes128Gcm)
	if err != nil {
		t.Fatal(err)
	}

	info, _ := hex.DecodeString("4f6465206f6e2061204772656369616e2055726e")

	serverSeed, _ := hex.DecodeString("6d9014e4609687b0a3670a22f2a14eac5ae6ad8c0beb62fb3ecb13dc8ebf5e06")
	serverKp, err := ctx.DeterministicKeyPair(serverSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !hexEqual(serverKp.SecretKey, "ecaf25b8485bcf40b9f013dbb96a6230f25733b8435bba0997a1dedbc7f78806") {
		t.Fatal("Unexpected serverSk")
	}
	if !hexEqual(serverKp.PublicKey, "a5912b20892e36905bac635267e2353d58f8cc7525271a2bf57b9c48d2ec2c07") {
		t.Fatal("Unexpected serverPk")
	}

	clientSeed, _ := hex.DecodeString("6305de86b3cec022fae6f2f2d2951f0f90c8662112124fd62f17e0a99bdbd08e")
	clientCtx, encryptedSharedSecret, err := ctx.NewClientDeterministicContext(serverKp.PublicKey, info, nil, clientSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !hexEqual(encryptedSharedSecret, "950897e0d37a8bdb0f2153edf5fa580a64b399c39fbb3d014f80983352a63617") {
		t.Fatal("Unexpected shared secret")
	}

	c1, _ := clientCtx.EncryptToServer([]byte("message"), []byte("ad"))
	if !hexEqual(c1, "bb18e3a813f39935e8a98ea0601c9163def047256e3b9e") {
		t.Fatal("Unexpected ciphertext")
	}

	c2, _ := clientCtx.EncryptToServer([]byte("message"), []byte("ad"))
	if !hexEqual(c2, "5bd68e679c85d412c519a72e602ac194a48fa6cb65fb58") {
		t.Fatal("Unexpected second ciphertext")
	}

	if !hexEqual(clientCtx.inner.outboundState.baseNonce, "5d99b2f03c452f7a9441933a") {
		t.Fatal("Unexpected base nonce")
	}

	es := clientCtx.ExporterSecret()
	if !hexEqual(es, "00c3cdacab28e981cc907d12e4f55f0aacae261dbb4eb610447a6bc431bfe2aa") {
		t.Fatal("Unexpected exported secret")
	}
}

func TestExportOnly(t *testing.T) {
	suite, err := NewSuite(KemX25519HkdfSha256, KdfHkdfSha256, AeadExportOnly)
	if err != nil {
		t.Fatal(err)
	}

	serverKp, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	clientCtx, encryptedSharedSecret, err := suite.NewClientContext(serverKp.PublicKey, []byte("test"), nil)
	if err != nil {
		t.Fatal(err)
	}

	serverCtx, err := suite.NewServerContext(encryptedSharedSecret, serverKp, []byte("test"), nil)
	if err != nil {
		t.Fatal(err)
	}

	es := serverCtx.ExporterSecret()
	for i, x := range clientCtx.ExporterSecret() {
		if es[i] != x {
			t.Fatal("Exported secret mismatch")
		}
	}
}

func hexEqual(a []byte, bHex string) bool {
	b, _ := hex.DecodeString(bHex)
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
