//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32            = syscall.NewLazyDLL("user32.dll")
	procFindWindowW      = modUser32.NewProc("FindWindowW")
	procSetClassLongPtrW = modUser32.NewProc("SetClassLongPtrW")
	procInvalidateRect   = modUser32.NewProc("InvalidateRect")
)

// GCLP_HBRBACKGROUND：窗口类背景画刷，WM_ERASEBKGND 会用它在客户区填充不透明背景。
// Win32 中该索引为 -10（按有符号 int 处理）。
const gclpHbrBackground = -10

// isWindows11OrGreater 判断系统是否为 Windows 11 22621+（支持系统级 Mica 后层）。
func isWindows11OrGreater() bool {
	major, minor, build := windows.RtlGetNtVersionNumbers()
	return major == 10 && minor == 0 && build >= 22621
}

// enableWindowsMica 让 Windows 11 的 Mica 毛玻璃真正透出：
// Wails 在初始化时会用 options.BackgroundColour 设置一个不透明的类背景刷，
// 它会把 DWM 绘制的 Mica 后层完全盖住（这也是"开启 BackdropType=Mica 后
// 界面看起来没变化"的根因）。这里把类背景刷置空并强制重绘，
// 使透明 WebView 下能透出 Mica。仅在 Windows 11 22621+ 生效，任何失败静默跳过。
func enableWindowsMica() {
	if !isWindows11OrGreater() {
		return
	}

	// 通过窗口标题定位主窗口句柄（main.go 中 Title 设为 "CryptoKit"）
	title, err := syscall.UTF16PtrFromString("CryptoKit")
	if err != nil {
		return
	}
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return
	}

	// 置空类背景刷（0 = NULL 画刷，WM_ERASEBKGND 不再填充不透明底色）
	// 注意：负常量不能直接转 uintptr，需先经运行时变量
	idx := int32(gclpHbrBackground)
	procSetClassLongPtrW.Call(hwnd, uintptr(idx), 0)
	// 强制整窗重绘，让透明区域立刻透出 Mica
	procInvalidateRect.Call(hwnd, 0, 1)
}
