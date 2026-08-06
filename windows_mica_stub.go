//go:build !windows

package main

// enableWindowsMica 为非 Windows 平台提供的空实现（macOS / Linux 无 Mica 概念）。
func enableWindowsMica() {}
