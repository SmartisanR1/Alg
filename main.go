package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:         "CryptoKit — 全平台密码算法工具箱",
		Width:         1400,
		Height:        900,
		MinWidth:      1100,
		MinHeight:     700,
		DisableResize: false,
		Fullscreen:    false,
		Frameless:     false,
		// 秒开关键: 隐藏启动，DOM就绪后在 domReady() 中调用 WindowShow
		// 彻底消除 Windows 下 WebView2 初始化时的白屏等待感
		StartHidden:       true,
		HideWindowOnClose: false,
		BackgroundColour:  &options.RGBA{R: 18, G: 18, B: 26, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		Menu:             nil,
		Logger:           nil,
		LogLevel:         0,
		OnStartup:        app.startup,
		OnDomReady:       app.domReady,
		OnBeforeClose:    app.beforeClose,
		OnShutdown:       app.shutdown,
		WindowStartState: options.Normal,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: false,
			WebviewUserDataPath:               "",
			WebviewBrowserPath:                "",
			Theme:                             windows.SystemDefault,
			CustomTheme: &windows.ThemeSettings{
				DarkModeTitleBar:   windows.RGB(18, 18, 26),
				DarkModeTitleText:  windows.RGB(240, 240, 240),
				DarkModeBorder:     windows.RGB(40, 40, 55),
				LightModeTitleBar:  windows.RGB(248, 248, 252),
				LightModeTitleText: windows.RGB(30, 30, 30),
				LightModeBorder:    windows.RGB(200, 200, 210),
			},
		},
		Mac: &mac.Options{
			TitleBar:             mac.TitleBarHiddenInset(),
			Appearance:           mac.NSAppearanceNameDarkAqua,
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			About: &mac.AboutInfo{
				Title:   "CryptoKit",
				Message: "全平台密码算法工具箱 v1.0.0\n支持国密 / 国际 / PQC 算法",
			},
		},
		Linux: &linux.Options{
			Icon:                []byte{},
			WindowIsTranslucent: false,
			WebviewGpuPolicy:    linux.WebviewGpuPolicyOnDemand,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
