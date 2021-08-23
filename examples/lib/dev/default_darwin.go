package dev

import (
	"github.com/trustasia-com/ble"
	"github.com/trustasia-com/ble/darwin"
)

// DefaultDevice ...
func DefaultDevice(opts ...ble.Option) (d ble.Device, err error) {
	return darwin.NewDevice(opts...)
}
