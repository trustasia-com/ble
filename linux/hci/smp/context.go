// Package smp provides ...
package smp

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/trustasia-com/go-van/pkg/logx"
)

// pairing type
const (
	JustWorks = iota
	NumericComp
	Passkey
	Oob
)

var pairingTypeStrings = map[int]string{
	JustWorks:   "Just Works",
	NumericComp: "Numeric Comparison",
	Passkey:     "Passkey Entry",
	Oob:         "OOB Data",
}

//Core spec v5.0 Vol 3, Part H, 2.3.5.1
//Tables 2.6, 2.7, and 2.8
var ioCapsTableSC = [][]int{
	{JustWorks, JustWorks, Passkey, JustWorks, Passkey},
	{JustWorks, NumericComp, Passkey, JustWorks, NumericComp},
	{Passkey, Passkey, Passkey, JustWorks, Passkey},
	{JustWorks, JustWorks, JustWorks, JustWorks, JustWorks},
	{Passkey, NumericComp, Passkey, JustWorks, NumericComp},
}

var ioCapsTableLegacy = [][]int{
	{JustWorks, JustWorks, Passkey, JustWorks, Passkey},
	{JustWorks, JustWorks, Passkey, JustWorks, Passkey},
	{Passkey, Passkey, Passkey, JustWorks, Passkey},
	{JustWorks, JustWorks, JustWorks, JustWorks, JustWorks},
	{Passkey, Passkey, Passkey, JustWorks, Passkey},
}

type pairingContext struct {
	request        Config
	response       Config
	remoteAddr     []byte
	remoteAddrType byte
	remoteRandom   []byte
	remoteConfirm  []byte

	localAddr     []byte
	localAddrType byte
	localRandom   []byte
	localConfirm  []byte

	scECDHKeys         *KeyPair
	scMacKey           []byte
	scRemotePubKey     crypto.PublicKey
	scDHKey            []byte
	scRemoteDHKeyCheck []byte

	legacy       bool
	shortTermKey []byte

	passKeyIteration int

	pairingType int
	state       PairingState
	authData    AuthData
	bond        bondInfo
}

func (ctx *pairingContext) checkDHKeyCheck() error {
	//F6(MacKey, Na, Nb, ra, IOcapA, A, B)
	la := ctx.localAddr
	la = append(la, ctx.localAddrType)
	rAddr := ctx.remoteAddr
	rAddr = append(rAddr, ctx.remoteAddrType)
	na := ctx.localRandom
	nb := ctx.remoteRandom

	ioCap := SwapBuf([]byte{ctx.response.AuthReq, ctx.response.OOBFlag, ctx.response.IOCap})

	ra := make([]byte, 16)
	if ctx.pairingType == Passkey {
		keyBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(keyBytes, uint32(ctx.authData.Passkey))
		ra[12] = keyBytes[0]
		ra[13] = keyBytes[1]
		ra[14] = keyBytes[2]
		ra[15] = keyBytes[3]

		//swap to little endian
		ra = SwapBuf(ra)
	} else if ctx.pairingType == Oob {
		ra = ctx.authData.OOBData
		//todo: does this need to be swapped?
	}

	dhKeyCheck, err := smpF6(ctx.scMacKey, nb, na, ra, ioCap, rAddr, la)
	if err != nil {
		return err
	}

	if !bytes.Equal(ctx.scRemoteDHKeyCheck, dhKeyCheck) {
		return fmt.Errorf("dhKeyCheck failed: expected %x, calculated %x",
			ctx.scRemoteDHKeyCheck, dhKeyCheck)
	}

	return nil
}

func (ctx *pairingContext) checkLegacyConfrim() error {
	preq := ctx.request.toSlice(PairingRequest)
	pres := ctx.response.toSlice(PairingResponse)
	la := ctx.localAddr
	ra := ctx.remoteAddr
	sRand := ctx.remoteRandom

	k := make([]byte, 16)
	if ctx.pairingType == Passkey {
		k = getLegacyParingTK(ctx.authData.Passkey)
	}
	c1, err := smpC1(k, sRand, preq, pres,
		ctx.localAddrType,
		ctx.remoteAddrType,
		la,
		ra,
	)
	if err != nil {
		return err
	}

	sConfirm := ctx.remoteConfirm

	if !bytes.Equal(sConfirm, c1) {
		return fmt.Errorf("sConfirm does not match: exp %s calc %s",
			hex.EncodeToString(sConfirm), hex.EncodeToString(c1))
	}

	return nil
}

// todo: key should be set at the beginning
func (ctx *pairingContext) generatePassKeyConfirm() ([]byte, []byte) {
	e := ellipticECDH{elliptic.P256()}
	kbx := e.MarshalX(ctx.scRemotePubKey)
	kax := e.MarshalX(ctx.scECDHKeys.publicKey)
	nai := make([]byte, 16)
	_, err := rand.Read(nai)
	if err != nil {

	}

	i := ctx.passKeyIteration
	z := 0x80 | (byte)((ctx.authData.Passkey&(1<<uint(i)))>>uint(i))

	calcConf, err := smpF4(kax, kbx, nai, z)
	if err != nil {
		logx.Errorf("generatePasskeyConfirm: %v", err)
	}

	//ctx.Debugf("passkey confirm %d: z: %x, conf: %v", iteration, z, hex.EncodeToString(calcConf))

	return calcConf, nai
}

func (ctx *pairingContext) checkPasskeyConfirm() error {
	// make the keys work as expected
	e := ellipticECDH{elliptic.P256()}
	kbx := e.MarshalX(ctx.scRemotePubKey)
	kax := e.MarshalX(ctx.scECDHKeys.publicKey)
	nb := ctx.remoteRandom
	i := ctx.passKeyIteration
	key := ctx.authData.Passkey

	// this gets the bits of the passkey for the current iteration
	z := 0x80 | (byte)((key&(1<<uint(i)))>>uint(i))

	//Cb =f4(PKbx,PKax, Nb, rb)
	calcConf, err := smpF4(kbx, kax, nb, z)
	if err != nil {
		return err
	}

	//ctx.Debugf("i: %d, z: %x, c: %v, cc: %v, ra: %v, rb: %v", iteration, z,
	//	hex.EncodeToString(p.remoteConfirm),
	//	hex.EncodeToString(calcConf),
	//	hex.EncodeToString(p.localRandom),
	//	hex.EncodeToString(p.remoteRandom))

	if !bytes.Equal(ctx.remoteConfirm, calcConf) {
		return fmt.Errorf("passkey confirm mismatch %d, exp %v got %v",
			i, hex.EncodeToString(ctx.remoteConfirm), hex.EncodeToString(calcConf))
	}
	return nil
}

func (ctx *pairingContext) checkConfirm() error {
	e := ellipticECDH{elliptic.P256()}
	//Cb =f4(PKbx,PKax, Nb, 0 )
	// make the keys work as expected
	kbx := e.MarshalX(ctx.scRemotePubKey)
	kax := e.MarshalX(ctx.scECDHKeys.publicKey)
	nb := ctx.remoteRandom

	calcConf, err := smpF4(kbx, kax, nb, 0)
	if err != nil {
		return err
	}

	if !bytes.Equal(calcConf, ctx.remoteConfirm) {
		return fmt.Errorf("confirm mismatch, exp %v got %v",
			hex.EncodeToString(ctx.remoteConfirm), hex.EncodeToString(calcConf))
	}

	return nil
}

func (ctx *pairingContext) calcMacLtk() error {
	err := ctx.generateDHKey()
	if err != nil {
		return err
	}

	// MacKey || LTK = f5(DHKey, N_master, N_slave, BD_ADDR_master,BD_ADDR_slave)
	la := ctx.localAddr
	la = append(la, ctx.localAddrType)
	ra := ctx.remoteAddr
	ra = append(ra, ctx.remoteAddrType)
	na := ctx.localRandom
	nb := ctx.remoteRandom

	mk, ltk, err := smpF5(ctx.scDHKey, na, nb, la, ra)
	if err != nil {
		return err
	}

	ctx.bond = bondInfo{

		longTermKey: ltk,
		ediv:        0,
		randVal:     0,
		legacy:      false,
	}
	ctx.scMacKey = mk

	return nil
}

func (ctx *pairingContext) generateDHKey() error {
	if ctx == nil || ctx.scECDHKeys == nil {
		return fmt.Errorf("nil keys")
	}

	if ctx.scRemotePubKey == nil {
		return fmt.Errorf("missing remote public key")
	}

	prv := ctx.scECDHKeys.privateKey

	e := ellipticECDH{elliptic.P256()}
	dk, err := e.GenerateSecret(prv, ctx.scRemotePubKey)
	if err != nil {
		return err
	}
	ctx.scDHKey = dk
	return nil
}

func determinePairingType(ctx *pairingContext) int {
	mitmMask := byte(0x04)

	req := ctx.request
	resp := ctx.response
	if req.OOBFlag == 0x01 && resp.OOBFlag == 0x01 && ctx.legacy {
		return Oob
	}

	if req.OOBFlag == 0x01 || resp.OOBFlag == 0x01 {
		return Oob
	}

	if req.AuthReq&mitmMask == 0x00 && resp.AuthReq&mitmMask == 0x00 {
		return JustWorks
	}

	pairingTypeTable := ioCapsTableSC
	if ctx.legacy {
		pairingTypeTable = ioCapsTableLegacy
	}
	if resp.IOCap >= IOCapReservedStart || req.IOCap >= IOCapReservedStart {
		logx.Warningf("determinePairingType: invalid io capabilities specified: req: %x rsp: %x",
			req.IOCap, resp.IOCap)
		logx.Warning("determinePairingType: using just works")
		return JustWorks
	}
	return pairingTypeTable[int(resp.IOCap)][int(req.IOCap)]
}
