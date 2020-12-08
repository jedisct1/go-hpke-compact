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

	serverPk, serverSk, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	clientCtx, encryptedSharedSecret, err := suite.NewClientContext(serverPk, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	serverCtx, err := suite.NewServerContext(encryptedSharedSecret, serverPk, serverSk, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := clientCtx.Encrypt([]byte("message"), nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := serverCtx.Decrypt(ciphertext, nil)
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

	serverSeed, _ := hex.DecodeString("8a219e9a42233826f165d2c1036399fa84cfb3bcb93872bc49287dfbe6f1fec9")
	serverPk, serverSk, err := ctx.DeterministicKeyPair(serverSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !hexEqual(serverSk, "490e958c0a0a03ab89cd09e2cb5a2232b30447df71b0288b96eb5d59cab13101") {
		t.Fatal("Unexpected serverSk")
	}
	if !hexEqual(serverPk, "693e421a7747f0b5cc05716351a9409de672d205f2a178ed70294c7afad22620") {
		t.Fatal("Unexpected serverPk")
	}

	clientSeed, _ := hex.DecodeString("591c66abd531b9c8287cf76ac053efba38d61e994e7f656c30dab6723a8af9ce")
	clientCtx, encryptedSharedSecret, err := ctx.NewClientDeterministicContext(serverPk, info, clientSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !hexEqual(encryptedSharedSecret, "b6e788b2785b5db5e76a752f1a4a7b33e58bb7de3744289450c9254049824950") {
		t.Fatal("Unexpected shared secret")
	}

	c1, _ := clientCtx.Encrypt([]byte("message"), []byte("ad"))
	if !hexEqual(c1, "24fadb5b67c40fa465fc728b1a3a85121ea9cf525dc26b") {
		t.Fatal("Unexpected ciphertext")
	}

	c2, _ := clientCtx.Encrypt([]byte("message"), []byte("ad"))
	if !hexEqual(c2, "ac79f70c02702f923ea7c7edcd61a7996e0b0e59a68ca6") {
		t.Fatal("Unexpected second ciphertext")
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
