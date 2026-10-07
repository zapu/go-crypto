//go:build testtool

// Command test-tool writes two public keys whose direct signatures contain a
// hashed revocation-key subpacket that is not a full fingerprint. Both
// signatures are valid. Run with:
//
//	go run -tags testtool ./openpgp/test-tool
package main

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"time"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/keybase/go-crypto/openpgp/packet"
	"github.com/keybase/go-crypto/rsa"
)

func main() {
	cfg := &packet.Config{
		Time: func() time.Time { return time.Unix(1577836800, 0) },
	}
	shortBody := []byte{0x80, byte(packet.PubKeyAlgoRSA), 0x01}
	truncBody := []byte{0x80}

	short, err := armoredKey(cfg, shortBody)
	if err != nil {
		panic(err)
	}
	trunc, err := armoredKey(cfg, truncBody)
	if err != nil {
		panic(err)
	}

	fmt.Printf("SHORT:\n%sTRUNC:\n%s", short, trunc)
}

func armoredKey(cfg *packet.Config, revokerBody []byte) (string, error) {
	now := cfg.Now()
	revokee, err := rsa.GenerateKey(cfg.Random(), 2048)
	if err != nil {
		return "", err
	}
	revoker, err := rsa.GenerateKey(cfg.Random(), 2048)
	if err != nil {
		return "", err
	}
	revokeeKey := packet.NewRSAPrivateKey(now, revokee)
	revokerKey := packet.NewRSAPrivateKey(now, revoker)

	direct := &packet.Signature{
		CreationTime: now,
		SigType:      packet.SigTypeDirectSignature,
		PubKeyAlgo:   packet.PubKeyAlgoRSA,
		Hash:         crypto.SHA256,
		IssuerKeyId:  &revokeeKey.KeyId,
	}
	if err := packet.SignDirectWithRevocationKeyBody(direct, &revokeeKey.PublicKey, revokeeKey, cfg, revokerBody); err != nil {
		return "", err
	}
	if err := revokeeKey.VerifyRevocationSignature(&revokeeKey.PublicKey, direct); err != nil {
		return "", fmt.Errorf("direct signature does not verify: %w", err)
	}

	uid := packet.NewUserId("Revokee", "", "")
	self := &packet.Signature{
		CreationTime: now,
		SigType:      packet.SigTypePositiveCert,
		PubKeyAlgo:   packet.PubKeyAlgoRSA,
		Hash:         crypto.SHA256,
		IssuerKeyId:  &revokeeKey.KeyId,
		FlagsValid:   true,
		FlagCertify:  true,
		FlagSign:     true,
	}
	if err := self.SignUserId(uid.Id, &revokeeKey.PublicKey, revokeeKey, cfg); err != nil {
		return "", err
	}

	revocation := &packet.Signature{
		CreationTime: now,
		SigType:      packet.SigTypeKeyRevocation,
		PubKeyAlgo:   packet.PubKeyAlgoRSA,
		Hash:         crypto.SHA256,
		IssuerKeyId:  &revokerKey.KeyId,
	}
	if err := packet.SignKeyRevocation(revocation, &revokeeKey.PublicKey, revokerKey, cfg); err != nil {
		return "", err
	}
	if err := revokerKey.VerifyRevocationSignature(&revokeeKey.PublicKey, revocation); err != nil {
		return "", fmt.Errorf("revocation signature does not verify: %w", err)
	}

	var raw bytes.Buffer
	for _, w := range []interface{ Serialize(io.Writer) error }{
		&revokeeKey.PublicKey,
		direct,
		uid,
		self,
		revocation,
	} {
		if err := w.Serialize(&raw); err != nil {
			return "", err
		}
	}

	var out bytes.Buffer
	block, err := armor.Encode(&out, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	if _, err := block.Write(raw.Bytes()); err != nil {
		return "", err
	}
	if err := block.Close(); err != nil {
		return "", err
	}
	return out.String(), nil
}
