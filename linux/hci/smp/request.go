// Package smp provides ...
package smp

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"

	"github.com/pkg/errors"
)

// RequestPairingRequest pairing request
func (m *Manager) RequestPairingRequest() ([]byte, error) {
	return m.config.toSlice(PairingRequest), nil
}

// RequestPairingPublicKey return publickey data
func (m *Manager) RequestPairingPublicKey() ([]byte, error) {
	ctx := m.context

	if ctx.scECDHKeys == nil {
		pair, err := GenerateECDHPair()
		if err != nil {
			return nil, err
		}
		ctx.scECDHKeys = pair
	}

	k := ellipticECDH{elliptic.P256()}.Marshal(ctx.scECDHKeys.publicKey)
	ctx.state = WaitPublicKey
	out := append([]byte{PairingPublicKey}, k...)
	return out, nil
}

// RequestPairingRandom pairing random
func (m *Manager) RequestPairingRandom() ([]byte, error) {
	ctx := m.context
	if ctx == nil {
		return nil, errors.New("no pairing context")
	}

	if ctx.localRandom == nil {
		r := make([]byte, 16)
		_, err := rand.Read(r)
		if err != nil {
			return nil, err
		}
		ctx.localRandom = r
	}

	ctx.state = WaitRandom
	out := append([]byte{PairingRandom}, ctx.localRandom...)
	return out, nil
}

func getLegacyParingTK(key int) []byte {
	tk := make([]byte, 16)
	keyBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(keyBytes, uint32(key))
	tk[12] = keyBytes[0]
	tk[13] = keyBytes[1]
	tk[14] = keyBytes[2]
	tk[15] = keyBytes[3]

	tk = SwapBuf(tk)

	return tk
}

// RequestPairingConfirm m confirm
func (m *Manager) RequestPairingConfirm() ([]byte, error) {
	ctx := m.context
	if ctx == nil {
		return nil, errors.New("no pairing context")
	}

	preq := ctx.request.toSlice(PairingRequest)
	presp := ctx.response.toSlice(PairingResponse)

	r := make([]byte, 16)
	_, err := rand.Read(r)
	if err != nil {
		return nil, err
	}
	ctx.localRandom = r

	la := ctx.localAddr
	lat := ctx.localAddrType
	ra := ctx.remoteAddr
	rat := ctx.remoteAddrType

	k := make([]byte, 16)
	if ctx.pairingType == Passkey {
		k = getLegacyParingTK(ctx.authData.Passkey)
	}
	c1, err := smpC1(k, r, preq, presp, lat, rat, la, ra)
	if err != nil {
		return nil, err
	}
	ctx.state = WaitConfirm
	out := append([]byte{PairingConfirm}, c1...)
	return out, nil
}

// RequestDHKeyCheck dhkey check
func (m *Manager) RequestDHKeyCheck() ([]byte, error) {
	ctx := m.context
	if ctx == nil {
		return nil, errors.New("no pairing context")
	}

	//Ea = f6 (MacKey, Na, Nb, rb, IOcapA, A, B)
	la := append(ctx.localAddr, ctx.localAddrType)
	ra := append(ctx.remoteAddr, ctx.remoteAddrType)
	na := ctx.localRandom
	nb := ctx.remoteRandom

	ioCap := SwapBuf([]byte{ctx.request.AuthReq, ctx.request.OOBFlag, ctx.request.IOCap})

	rb := make([]byte, 16)
	if ctx.pairingType == Passkey {
		keyBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(keyBytes, uint32(ctx.authData.Passkey))
		rb[12] = keyBytes[0]
		rb[13] = keyBytes[1]
		rb[14] = keyBytes[2]
		rb[15] = keyBytes[3]

		//swap to little endian
		rb = SwapBuf(rb)
	} else if ctx.pairingType == Oob {
		rb = ctx.authData.OOBData
		//todo: does this need to be swapped?
	}

	ea, err := smpF6(ctx.scMacKey, na, nb, rb, ioCap, la, ra)
	if err != nil {
		return nil, err
	}

	ctx.state = WaitDhKeyCheck
	out := append([]byte{PairingDHKeyCheck}, ea...)
	return out, nil
}
