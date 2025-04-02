package interfaces

import "crypto/ecdsa"

type Verifier interface {
	VerifyASN1WithSM2(pub *ecdsa.PublicKey, uid, msg, sig []byte) bool
}
