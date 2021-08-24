// Package smp provides ...
package smp

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/trustasia-com/go-van/pkg/logx"
)

//Core spec v5.0, Vol 3, Part H, 3.5.5, Table 3.7
var pairingFailedReason = map[byte]string{
	0x0: "reserved",
	0x1: "passkey entry failed",
	0x2: "oob not available",
	0x3: "authentication requirements",
	0x4: "confirm value failed",
	0x5: "pairing not support",
	0x6: "encryption key size",
	0x7: "command not supported",
	0x8: "unspecified reason",
	0x9: "repeated attempts",
	0xa: "invalid parameters",
	0xb: "DHKey check failed",
	0xc: "numeric comparison failed",
	0xd: "BR/EDR pairing in progress",
	0xe: "cross-transport key derivation/generation not allowed",
}

func isLegacy(authReq byte) bool {
	if authReq&0x08 == 0x08 {
		return false
	}
	return true
}

// ResponsePairingResponse pairing response
func (m *Manager) ResponsePairingResponse(in []byte) ([]byte, error) {
	ctx := m.context
	if len(in) < 6 {
		return nil, errors.New(hex.EncodeToString(in) + ", invalid length")
	}

	rx := Config{}
	rx.IOCap = in[0]
	rx.OOBFlag = in[1]
	rx.AuthReq = in[2]
	rx.MaxKeySize = in[3]
	rx.InitKeyDist = in[4]
	rx.RespKeyDist = in[5]
	ctx.response = rx

	ctx.pairingType = JustWorks
	ctx.passKeyIteration = 0

	ctx.legacy = isLegacy(rx.AuthReq)
	ctx.pairingType = determinePairingType(ctx)

	pts, ok := pairingTypeStrings[ctx.pairingType]
	if !ok {
		return nil, errors.Errorf("invalid pairing type %v", ctx.pairingType)
	}
	logx.Info("handlePairingResponse: detected pairing type: ", pts)
	if ctx.pairingType == Oob && len(ctx.authData.OOBData) == 0 {
		ctx.state = Error
		return nil, errors.New("pairing requires OOB data but OOB data not specified")
	}
	if ctx.legacy {
		return m.RequestPairingConfirm()
	}
	return m.RequestPairingPublicKey()
}

// ResponsePairingConfirm pairing confirm
func (m *Manager) ResponsePairingConfirm(in []byte) ([]byte, error) {
	ctx := m.context
	if ctx == nil {
		return nil, errors.New("no pairing context")
	}
	if len(in) != 16 {
		return nil, errors.New("invalid length")
	}
	ctx.remoteConfirm = in

	return m.RequestPairingRandom()
}

func onSecureRandom(m *Manager) ([]byte, error) {
	ctx := m.context
	if ctx.pairingType == Passkey {
		data, err := handlePassKeyRandom(ctx)
		if err != nil {
			return nil, err
		}
		if len(data) > 0 {
			return data, nil
		}
	} else {
		err := ctx.checkConfirm()
		if err != nil {
			logx.Errorf("checkConfirm %v", err)
			return nil, err
		}
	}

	// TODO
	// here we would do the compare from g2(...) but this is just works only for now
	// move on to auth stage 2 (2.3.5.6.5) calc mackey, ltk
	err := ctx.calcMacLtk()
	if err != nil {
		logx.Errorf("smpOnSecureRandom: calcMacLtk - %v", err)
		return nil, err
	}

	//send dhkey check
	return m.RequestDHKeyCheck()
}

func onLegacyRandom(m *Manager) ([]byte, error) {
	ctx := m.context

	err := ctx.checkLegacyConfrim()
	if err != nil {
		return nil, err
	}

	lRand := ctx.localRandom
	rRand := ctx.remoteRandom

	// calculate STK
	k := getLegacyParingTK(ctx.authData.Passkey)
	stk, err := smpS1(k, rRand, lRand)
	if err != nil {
		return nil, err
	}
	ctx.shortTermKey = stk

	if ctx.request.AuthReq&authReqBondMask == authReqNoBond {
		ctx.state = Finished
	}
	return m.Encrypt()
}

// ResponsePairingRandom pairing random
func (m *Manager) ResponsePairingRandom(in []byte) ([]byte, error) {
	ctx := m.context
	if ctx == nil {
		return nil, errors.New("no pairing context")
	}
	if len(in) != 16 {
		return nil, errors.New("invalid length")
	}

	ctx.remoteRandom = in
	// config check
	if ctx.legacy {
		return onLegacyRandom(m)
	}
	return onSecureRandom(m)
}

// ResponseEncryptionInformation encryption information
func (m *Manager) ResponseEncryptionInformation(in []byte) ([]byte, error) {
	ctx := m.context
	ctx.bond = bondInfo{
		longTermKey: in,
		ediv:        0,
		randVal:     0,
		legacy:      true,
	}
	return nil, nil
}

// ResponseMasterIdentification master identification
func (m *Manager) ResponseMasterIdentification(in []byte) ([]byte, error) {
	ctx := m.context

	ediv := binary.LittleEndian.Uint16(in[:2])
	randVal := binary.LittleEndian.Uint64(in[2:])

	ltk := ctx.bond.longTermKey
	ctx.bond = bondInfo{
		longTermKey: ltk,
		ediv:        ediv,
		randVal:     randVal,
		legacy:      true,
	}
	// save bond info
	if ctx.request.AuthReq&authReqBondMask == authReqBond {
		addr := hex.EncodeToString(ctx.remoteAddr)
		err := m.storage.Save(addr, ctx.bond)
		if err != nil {
			return nil, err
		}
	}
	ctx.state = Finished
	return nil, nil
}

// ResponseSecurityRequest security request
func (m *Manager) ResponseSecurityRequest(in []byte) ([]byte, error) {
	ctx := m.context
	if len(in) < 1 {
		return nil, errors.New(hex.EncodeToString(in) + ", invalid length")
	}
	// TODO clean this up
	rx := Config{}
	rx.AuthReq = in[0]

	if (rx.AuthReq & authReqBondMask) == authReqBond {
		ra := hex.EncodeToString(ctx.remoteAddr)
		bi, err := m.storage.Find(ra)
		if err == nil {
			ctx.bond = bi
			// TODO encrypter
			return m.Encrypt()
		}
		logx.Info("error: SecurityRequest: bond manager " + err.Error())
		// will re-bond below
	}

	// match the incoming request parameters
	ctx.request.AuthReq = rx.AuthReq
	// no bonding information stored, so trigger a bond
	return m.RequestPairingRequest()
}

func startPassKeyPairing(ctx *pairingContext) ([]byte, error) {
	ctx.passKeyIteration = 0

	return continuePassKeyPairing(ctx), nil
}

// ResponsePairingPublicKey pairing public key
func (m *Manager) ResponsePairingPublicKey(in []byte) ([]byte, error) {
	ctx := m.context
	if ctx == nil {
		return nil, errors.New("no pairing context")
	}
	if len(in) != 64 {
		return nil, errors.New("invalid length")
	}

	// validate the remote public key does not match our public key
	// CVE-2020-26558
	ecdh := ellipticECDH{elliptic.P256()}
	k := ecdh.Marshal(ctx.scECDHKeys.publicKey)
	if bytes.Equal(k, in) {
		return nil, errors.New("remote public key cannot match local public key")
	}
	pubKey, ok := ecdh.Unmarshal(in)
	if !ok {
		return nil, errors.New("invalid public key")
	}
	ctx.scRemotePubKey = pubKey
	if ctx.pairingType == Passkey {
		return startPassKeyPairing(ctx)
	}
	return nil, nil
}

// ResponsePairingDHKeyCheck pairing dh key
func (m *Manager) ResponsePairingDHKeyCheck(in []byte) ([]byte, error) {
	ctx := m.context
	if ctx == nil {
		return nil, errors.New("no pairing context")
	}

	ctx.scRemoteDHKeyCheck = in
	err := ctx.checkDHKeyCheck()
	if err != nil {
		return nil, err
	}

	// save bond info
	if ctx.request.AuthReq&authReqBondMask == authReqBond {
		addr := hex.EncodeToString(ctx.remoteAddr)
		err = m.storage.Save(addr, ctx.bond)
		if err != nil {
			return nil, err
		}
	}
	// at this point, the pairing is complete
	ctx.state = Finished

	// TODO: separate this out
	return m.Encrypt()
}

// ResponsePairingFailed pairing failed
func (m *Manager) ResponsePairingFailed(in []byte) ([]byte, error) {
	reason := "unknown"
	if len(in) > 0 {
		if r, ok := pairingFailedReason[in[0]]; ok {
			reason = r
		}
	}
	return nil, errors.New("pairing failed: " + reason)
}

func continuePassKeyPairing(ctx *pairingContext) []byte {
	confirm, random := ctx.generatePassKeyConfirm()
	ctx.localRandom = random
	out := append([]byte{PairingRandom}, confirm...)
	return out
}

func handlePassKeyRandom(ctx *pairingContext) ([]byte, error) {
	err := ctx.checkPasskeyConfirm()
	if err != nil {
		return nil, err
	}
	ctx.passKeyIteration++

	if ctx.passKeyIteration < passkeyIterationCount {
		return continuePassKeyPairing(ctx), nil
	}
	return nil, nil
}
