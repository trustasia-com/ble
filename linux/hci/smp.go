package hci

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/trustasia-com/ble/linux/hci/smp"
)

func (c *Conn) sendSMP(p pdu) error {
	buf := bytes.NewBuffer(make([]byte, 0))
	if err := binary.Write(buf, binary.LittleEndian, uint16(4+len(p))); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, cidSMP); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, p); err != nil {
		return err
	}
	_, err := c.writePDU(buf.Bytes())
	logger.Debug("smp", "send", fmt.Sprintf("[%X]", buf.Bytes()))
	return err
}

func (c *Conn) handleSMP(p pdu) error {
	fmt.Println("smp", "recv", fmt.Sprintf("[%X] %v", p, p))
	code := p[0]
	switch code {
	case smp.PairingRequest:
	case smp.PairingResponse:
	case smp.PairingConfirm:
	case smp.PairingRandom:
	case smp.PairingFailed:
	case smp.EncryptionInformation:
	case smp.MasterIdentification:
	case smp.IdentiInformation:
	case smp.IdentityAddreInformation:
	case smp.SigningInformation:
	case smp.SecurityRequest:
	case smp.PairingPublicKey:
	case smp.PairingDHKeyCheck:
	case smp.PairingKeypress:
	default:
		// If a packet is received with a reserved Code it shall be ignored. [Vol 3, Part H, 3.3]
		return nil
	}
	// FIXME: work aound to the lack of SMP implementation - always return non-supported.
	// C.5.1 Pairing Not Supported by Slave
	return c.sendSMP([]byte{smp.PairingFailed, 0x05})
}
