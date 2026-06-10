// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "syscall"

const ioctlReadTermios = uintptr(syscall.TCGETS)
