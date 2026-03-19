package mmtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"math/big"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

var curve = elliptic.P256()

func generateKeyPairs() (pub, verify *ecdsa.PrivateKey, err error) {
	pub, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	verify, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, verify, nil
}

func computeEphemeralSecret(x, y *big.Int, d *big.Int) []byte {
	r, _ := elliptic.P256().ScalarMult(x, y, d.Bytes())
	s := sha256.Sum256(r.Bytes())
	return s[:]
}

func computeTrafficKeyN(shareKey, info []byte, n int) (*trafficKeyPair, error) {
	trafficKey := make([]byte, n)
	if _, err := hkdf.Expand(sha256.New, shareKey, info).Read(trafficKey); err != nil {
		return nil, err
	}

	log.Debugf("TrafficKey(%d):\n%s\n", n, hex.Dump(trafficKey))

	pair := &trafficKeyPair{}
	if n == 56 {
		pair.clientKey = trafficKey[:16]
		pair.serverKey = trafficKey[16:32]
		pair.clientNonce = trafficKey[32:44]
		pair.serverNonce = trafficKey[44:]
	} else if n == 28 {
		pair.serverKey = trafficKey[:16]
		pair.serverNonce = trafficKey[16:]
	}

	return pair, nil
}

func verifyEcdsaSignature(handshakeHash hash.Hash, data []byte) bool {
	dataHash := sha256.Sum256(handshakeHash.Sum(nil))
	return ecdsa.VerifyASN1(ServerEcdh, dataHash[:], data)
}

func buildHkdfInfo(prefix string, h hash.Hash) []byte {
	info := []byte(prefix)
	if h != nil {
		info = append(info, h.Sum(nil)...)
	}
	return info
}

func computeHmac(k, d []byte) []byte {
	hm := hmac.New(sha256.New, k)
	hm.Write(d)
	return hm.Sum(nil)
}
