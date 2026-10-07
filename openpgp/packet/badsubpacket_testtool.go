//go:build testtool

package packet

import (
	"hash"
	"strconv"

	"github.com/keybase/go-crypto/openpgp/errors"
	"github.com/keybase/go-crypto/rsa"
)

// SignDirectWithRevocationKeyBody signs a direct-key signature over key.
// The hashed area is the usual subpackets plus one revocation-key subpacket
// whose body is body, which may be shorter than a well-formed revocation key.
// Sign is not used: it replaces outSubpackets and would drop body.
func SignDirectWithRevocationKeyBody(sig *Signature, key *PublicKey, priv *PrivateKey, config *Config, body []byte) error {
	h, err := keyRevocationHash(key, sig.Hash)
	if err != nil {
		return err
	}
	sig.outSubpackets = sig.buildSubpackets()
	sig.outSubpackets = append(sig.outSubpackets, outputSubpacket{
		hashed:        true,
		subpacketType: revocationKeySubpacket,
		contents:      append([]byte(nil), body...),
	})
	return signPrepared(sig, h, priv, config)
}

// SignKeyRevocation signs a key revocation of revoked with priv.
func SignKeyRevocation(sig *Signature, revoked *PublicKey, priv *PrivateKey, config *Config) error {
	h, err := keyRevocationHash(revoked, sig.Hash)
	if err != nil {
		return err
	}
	return sig.Sign(h, priv, config)
}

func signPrepared(sig *Signature, h hash.Hash, priv *PrivateKey, config *Config) error {
	if priv == nil || priv.PrivateKey == nil {
		return errors.InvalidArgumentError("attempting to sign with nil PrivateKey")
	}
	digest, err := sig.signPrepareHash(h)
	if err != nil {
		return err
	}
	if sig.PubKeyAlgo != priv.PubKeyAlgo {
		return errors.InvalidArgumentError("signature pub key algo does not match priv key")
	}
	switch priv.PubKeyAlgo {
	case PubKeyAlgoRSA, PubKeyAlgoRSASignOnly:
		sig.RSASignature.bytes, err = rsa.SignPKCS1v15(config.Random(), priv.PrivateKey.(*rsa.PrivateKey), sig.Hash, digest)
		if err != nil {
			return err
		}
		sig.RSASignature.bitLength = uint16(8 * len(sig.RSASignature.bytes))
		return nil
	default:
		return errors.UnsupportedError("public key algorithm for signing: " + strconv.Itoa(int(priv.PubKeyAlgo)))
	}
}
