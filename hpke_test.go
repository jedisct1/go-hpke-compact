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

	serverSeed, _ := hex.DecodeString("29e5fcb544130784b7606e3160d736309d63e044c241d4461a9c9d2e9362f1db")
	serverKp, err := ctx.DeterministicKeyPair(serverSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !hexEqual(serverKp.SecretKey, "ad5e716159a11fdb33527ce98fe39f24ae3449ffb6e93e8911f62c0e9781718a") {
		t.Fatal("Unexpected serverSk")
	}
	if !hexEqual(serverKp.PublicKey, "46570dfa9f66e17c38e7a081c65cf42bc00e6fed969d326c692748ae866eac6f") {
		t.Fatal("Unexpected serverPk")
	}

	clientSeed, _ := hex.DecodeString("3b8ed55f38545e6ea459b6838280b61ff4f5df2a140823373380609fb6c68933")
	clientCtx, encryptedSharedSecret, err := ctx.NewClientDeterministicContext(serverKp.PublicKey, info, nil, clientSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !hexEqual(encryptedSharedSecret, "e7d9aa41faa0481c005d1343b26939c0748a5f6bf1f81fbd1a4e924bf0719149") {
		t.Fatal("Unexpected shared secret")
	}

	c1, _ := clientCtx.EncryptToServer([]byte("message"), []byte("ad"))
	if !hexEqual(c1, "dc54a1124854e041089e52066349a238380aaf6bf98a4c") {
		t.Fatal("Unexpected ciphertext")
	}

	c2, _ := clientCtx.EncryptToServer([]byte("message"), []byte("ad"))
	if !hexEqual(c2, "37fbdf5f21e77f15291212fe94579054f56eaf5e78f2b5") {
		t.Fatal("Unexpected second ciphertext")
	}

	if !hexEqual(clientCtx.inner.outboundState.baseNonce, "ede5198c19b2591389fc7cea") {
		t.Fatal("Unexpected base nonce")
	}

	es := clientCtx.ExporterSecret()
	if !hexEqual(es, "d27ca8c6ce9d8998f3692613c29e5ae0b064234b874a52d65a014eeffed429b9") {
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
