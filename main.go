package main

import (
	"embed"
	"os"
	"path/filepath"

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

	// 获取可执行文件所在目录，用于存放 WebView 数据
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	webviewDataDir := filepath.Join(exeDir, "webview-data")

	err := wails.Run(&options.App{
		Title:         "CryptoKit",
		Width:         1240,
		Height:        800,
		MinWidth:      1040,
		MinHeight:     680,
		DisableResize: false,
		Fullscreen:    false,
		Frameless:     false,
		// 隐藏启动：关闭以兼容 macOS 及国内网络（避免 Google Fonts 阻塞 domReady）
		StartHidden:       false,
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
			// Windows 11 Fluent Design：开启 Mica 半透明后层（Win10 及以下自动安全降级为不透明窗口）
			// 需配合 WebviewIsTransparent + WindowIsTranslucent，页面背景在 .platform-windows 下变为半透明毛玻璃
			WebviewIsTransparent:              true,
			WindowIsTranslucent:               true,
			BackdropType:                      windows.Mica,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: false,
			WebviewUserDataPath:               webviewDataDir,
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
