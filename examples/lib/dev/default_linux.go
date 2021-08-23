package dev

import (
	"github.com/trustasia-com/ble"
	"github.com/trustasia-com/ble/linux"
)

// DefaultDevice ...
func DefaultDevice(opts ...ble.Option) (d ble.Device, err error) {
	return linux.NewDevice(opts...)
}
