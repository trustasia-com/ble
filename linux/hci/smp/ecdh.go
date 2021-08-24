// Package smp provides ...
package smp

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

type publicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type privateKey struct {
	publicKey
	D []byte
}

// KeyPair key pair
type KeyPair struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
}

// GenerateECDHPair ecdh pair
func GenerateECDHPair() (*KeyPair, error) {
	curve := elliptic.P256()
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	privKey := &privateKey{
		D: priv,
	}
	privKey.Curve = curve
	privKey.X = x
	privKey.Y = y
	return &KeyPair{&privKey.publicKey, privKey}, nil
}

//
type ellipticECDH struct {
	curve elliptic.Curve
}

// Unmarshal point
func (e ellipticECDH) Unmarshal(data []byte) (crypto.PublicKey, bool) {
	var pubKey *publicKey
	var x, y *big.Int

	x, y = elliptic.Unmarshal(e.curve, data)
	if x == nil || y == nil {
		return pubKey, false
	}
	pubKey = &publicKey{
		Curve: e.curve,
		X:     x,
		Y:     y,
	}
	return pubKey, true
}

// Marshal marshal point
func (e ellipticECDH) Marshal(k crypto.PublicKey) []byte {
	pubKey := k.(publicKey)
	return elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
}

// MarshalX marshal x
func (e ellipticECDH) MarshalX(k crypto.PublicKey) []byte {
	ba := e.Marshal(k)
	ba = ba[1:] // remove header
	return SwapBuf(ba[:32])
}

// GenerateSecret generate share secret
func (e ellipticECDH) GenerateSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	key := privKey.(*privateKey)
	pub := privKey.(*publicKey)

	x, _ := e.curve.ScalarMult(pub.X, pub.Y, key.D)
	return x.Bytes(), nil
}
