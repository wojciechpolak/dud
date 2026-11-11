// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func tuiOpticalTestPTYName(master *os.File) (string, error) {
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return "", err
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	return fmt.Sprintf("/dev/pts/%d", number), err
}
