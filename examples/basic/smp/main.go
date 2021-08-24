package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/trustasia-com/ble"
	"github.com/trustasia-com/ble/examples/lib/dev"

	"github.com/pkg/errors"
)

var (
	device = flag.String("device", "default", "implementation of ble")
	du     = flag.Duration("du", 5*time.Second, "advertising duration, 0 for indefinitely")
)

func main() {
	flag.Parse()

	d, err := dev.NewDevice("default")
	if err != nil {
		log.Fatalf("can't new device : %s", err)
	}
	ble.SetDefaultDevice(d)

	ble.AddService(deviceInfoService())
	ble.AddService(batteryService())
	ble.AddService(genericAccessService())

	// Advertise for specified durantion, or until interrupted by user.
	fmt.Printf("Advertising for %s...\n", *du)
	chkErr(ble.AdvertiseNameAndServices(context.Background(), "Gopher"))
}

func chkErr(err error) {
	switch errors.Cause(err) {
	case nil:
	case context.DeadlineExceeded:
		fmt.Printf("done\n")
	case context.Canceled:
		fmt.Printf("canceled\n")
	default:
		log.Fatalf(err.Error())
	}
}

func deviceInfoService() *ble.Service {
	s := ble.NewService(ble.UUID16(0x180A))
	// Manufacturer Name string
	name := s.NewCharacteristic(ble.UUID16(0x2A29))
	name.SetValue([]byte("TrustAsia"))

	// Model Number string
	model := s.NewCharacteristic(ble.UUID16(0x2A24))
	model.SetValue([]byte("Fido2"))

	// Firmware Revision String
	firmware := s.NewCharacteristic(ble.UUID16(0x2A26))
	firmware.SetValue([]byte("1"))

	return s
}

func batteryService() *ble.Service {
	lv := byte(100)
	s := ble.NewService(ble.UUID16(0x180F))
	c := s.NewCharacteristic(ble.UUID16(0x2A19))
	c.HandleRead(
		ble.ReadHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
			rsp.Write([]byte{lv})
			lv--
		}),
	)

	// Characteristic User Description
	c.NewDescriptor(ble.UUID16(0x2901)).SetValue([]byte("Battery level between 0 and 100 percent"))

	// Characteristic Presentation Format
	c.NewDescriptor(ble.UUID16(0x2904)).SetValue([]byte{4, 1, 39, 173, 1, 0, 0})

	return s
}

var (
	// GenericAccessUUID 通过访问服务UUID
	GenericAccessUUID = ble.UUID16(0x1800)
	// DeviceNameUUID 设备名称UUID
	DeviceNameUUID = ble.UUID16(0x2A00)
	// AppearanceUUID 外貌UUID
	AppearanceUUID = ble.UUID16(0x2A01)
)

// genericAccessService generic access profile service
func genericAccessService() *ble.Service {
	s := ble.NewService(GenericAccessUUID)
	// Device name
	name := s.NewCharacteristic(DeviceNameUUID)
	name.SetValue([]byte("FIDO WeKey"))
	// Appearance
	model := s.NewCharacteristic(AppearanceUUID)
	model.SetValue([]byte("fido2"))
	return s
}
