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
	if !hexEqual(serverKp.SecretKey, "7bee22939481658190c6c12a1fccddec583af0ab1349e9c398e036ef6d920872") {
		t.Fatal("Unexpected serverSk")
	}
	if !hexEqual(serverKp.PublicKey, "201f8f0ff16db281729e21afbf035751f7ed62ce6da598f4a3ec1de50e573563") {
		t.Fatal("Unexpected serverPk")
	}

	clientSeed, _ := hex.DecodeString("6305de86b3cec022fae6f2f2d2951f0f90c8662112124fd62f17e0a99bdbd08e")
	clientCtx, encryptedSharedSecret, err := ctx.NewClientDeterministicContext(serverKp.PublicKey, info, nil, clientSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !hexEqual(encryptedSharedSecret, "4fa349feaa609d3202cf4246940dafc7381c390c7800d695b9c52ddaca40855c") {
		t.Fatal("Unexpected shared secret")
	}

	c1, _ := clientCtx.EncryptToServer([]byte("message"), []byte("ad"))
	if !hexEqual(c1, "7912debfb9f8f1391596328167b3d093f9beaafb5703b4") {
		t.Fatal("Unexpected ciphertext")
	}

	c2, _ := clientCtx.EncryptToServer([]byte("message"), []byte("ad"))
	if !hexEqual(c2, "15e0b66ff337ce9ea089e216bcbab1f7fcaa669470bb85") {
		t.Fatal("Unexpected second ciphertext")
	}

	if !hexEqual(clientCtx.inner.outboundState.baseNonce, "9e6b9543696720d2ad98e9ca") {
		t.Fatal("Unexpected base nonce")
	}

	es := clientCtx.ExporterSecret()
	if !hexEqual(es, "a94124e2580b7eba3bd20a3e908682297faf6ba3e565dc38f7fd7d74811a8bb0") {
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
