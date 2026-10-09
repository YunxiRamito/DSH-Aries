package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aries.local/aries/internal/client"
	"aries.local/aries/internal/kernel"
)

func coreLabel(core string, lang uiLanguage) string {
	if lang == langChinese {
		if core == "local" {
			return "本地核心"
		}
		return "在线核心（管理员令牌）"
	}
	if core == "local" {
		return "Local core"
	}
	return "Online core (admin token)"
}

func interactiveOutput(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
}

func showStartupAnimation(w io.Writer, lang uiLanguage) {
	if !interactiveOutput(w) {
		return
	}
	label := "Starting Aries control center"
	if lang == langChinese {
		label = "正在启动 Aries 控制台"
	}
	frames := []string{"◐", "◓", "◑", "◒"}
	for i := 0; i < 12; i++ {
		filled := strings.Repeat("━", i+1)
		empty := strings.Repeat("·", 12-i-1)
		fmt.Fprintf(w, "\r\x1b[36m%s\x1b[0m %s \x1b[35m[%s%s]\x1b[0m", frames[i%len(frames)], label, filled, empty)
		time.Sleep(65 * time.Millisecond)
	}
	fmt.Fprint(w, "\r\x1b[2K")
}

func selectLocalCore(prefs uiPreferences, reader *bufio.Reader, output io.Writer, lang uiLanguage) (uiPreferences, error) {
	text := languageText(lang)
	if prefs.ConfigPath == "" {
		fmt.Fprintf(output, "\n%s\n", text.setupTitle)
		root, err := askDefault(reader, output, text.installDir, "./aries-node")
		if err != nil && root == "" {
			return prefs, err
		}
		root, err = filepath.Abs(filepath.Clean(root))
		if err != nil {
			return prefs, err
		}
		configPath := filepath.Join(root, "config.json")
		if _, statErr := os.Stat(configPath); statErr == nil {
			prefs.ConfigPath = configPath
			prefs.TokenFile = filepath.Join(root, "secrets", "admin.token")
		} else {
			publicAddr, readErr := askDefault(reader, output, text.publicListen, "127.0.0.1:8787")
			if readErr != nil && publicAddr == "" {
				return prefs, readErr
			}
			fmt.Fprintf(output, "  %s\n", text.publicListenHint)
			adminAddr, readErr := askDefault(reader, output, text.adminListen, "127.0.0.1:8788")
			if readErr != nil && adminAddr == "" {
				return prefs, readErr
			}
			files, createErr := createDeploymentFiles(root, publicAddr, adminAddr)
			if createErr != nil {
				return prefs, createErr
			}
			prefs.ConfigPath = files.configPath
			prefs.TokenFile = files.tokenPath
			fmt.Fprintf(output, "%s\n  %s: %s\n  %s: %s\n  %s: %s\n", text.setupCreated, text.configPath, files.configPath, text.tokenPath, files.tokenPath, text.logPath, files.logPath)
		}
	}
	if prefs.ConfigPath == "" {
		return prefs, errors.New("local core config path is required")
	}
	if prefs.ServerExecutable == "" {
		prefs.ServerExecutable = findServerExecutable()
	}
	if prefs.ServerExecutable == "" {
		label := "aries-server executable path (leave blank to configure later)"
		if lang == langChinese {
			label = "aries-server 程序路径（可留空稍后配置）"
		}
		path, err := askDefault(reader, output, label, "")
		if err != nil && path == "" {
			return prefs, err
		}
		prefs.ServerExecutable = strings.TrimSpace(path)
	}
	prefs.Core = "local"
	if endpoint, tokenFile, err := localConnection(prefs.ConfigPath); err == nil {
		prefs.Endpoint, prefs.TokenFile = endpoint, tokenFile
	}
	return prefs, nil
}

func selectOnlineCore(prefs uiPreferences, o options, reader *bufio.Reader, output io.Writer, lang uiLanguage) (uiPreferences, options, error) {
	text := languageText(lang)
	fmt.Fprintf(output, "\n%s\n", text.existingTitle)
	endpointDefault := prefs.Endpoint
	if o.endpoint != "" {
		endpointDefault = o.endpoint
	}
	if endpointDefault == "" {
		endpointDefault = "https://server.example:8788"
	}
	endpoint, err := askDefault(reader, output, text.endpointPrompt, endpointDefault)
	if err != nil && endpoint == "" {
		return prefs, o, err
	}
	endpoint, err = normalizeEndpoint(endpoint)
	if err != nil {
		return prefs, o, err
	}
	tokenDefault := prefs.TokenFile
	if o.token != "" {
		tokenDefault = o.token
	}
	tokenFile, err := askDefault(reader, output, text.tokenPrompt, tokenDefault)
	if err != nil && tokenFile == "" {
		return prefs, o, err
	}
	if _, err = client.New(endpoint, tokenFile, o.timeout); err != nil {
		return prefs, o, err
	}
	prefs.Core, prefs.Endpoint, prefs.TokenFile = "online", endpoint, tokenFile
	o.endpoint, o.token = endpoint, tokenFile
	return prefs, o, nil
}

func localConnection(configPath string) (string, string, error) {
	config, err := kernel.LoadConfig(configPath)
	if err != nil {
		return "", "", err
	}
	if !isLoopbackListen(config.AdminListen) {
		return "", "", errors.New("local core admin listener must use loopback; remote administration requires HTTPS")
	}
	host, port, err := net.SplitHostPort(config.AdminListen)
	if err != nil {
		return "", "", err
	}
	if strings.EqualFold(host, "localhost") {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port), config.AdminTokenFile, nil
}

// runMainMenu drives the dashboard. rawInput is optional so callers and tests
// that provide a line-oriented reader keep working; the real UI passes its
// original stdin as the final argument and gets one-key terminal navigation.
func runMainMenu(o options, prefs uiPreferences, prefsPath string, lang uiLanguage, reader *bufio.Reader, output, errorsOut io.Writer, rawInputs ...io.Reader) error {
	var rawInput io.Reader
	if len(rawInputs) > 0 {
		rawInput = rawInputs[0]
	}
	selected := 0
	for {
		if prefs.Core == "local" && prefs.ConfigPath != "" && (o.endpoint == "" || o.token == "") {
			if endpoint, token, err := localConnection(prefs.ConfigPath); err == nil {
				o.endpoint, o.token = endpoint, token
			}
		}
		status, statusErr := fetchAdminStatus(o)
		// Enter raw mode only while waiting for the dashboard choice. Keeping
		// submenus in canonical mode means their existing text prompts continue
		// to work on both Unix and Windows terminals.
		keyboard, restore := beginMenuKeyboard(rawInput, output)
		var choice string
		var err error
		for {
			drawMainMenu(output, o, prefs, lang, status, statusErr == nil, selected, keyboard)
			var nextSelected int
			choice, nextSelected, err = readMenuAction(reader, rawInput, selected, 7, keyboard)
			if keyboard && err == nil {
				selected = nextSelected
			}
			if choice == "navigate" && err == nil {
				continue
			}
			break
		}
		if restore != nil {
			restore()
		}
		if errors.Is(err, io.EOF) && strings.TrimSpace(choice) == "" {
			fmt.Fprintln(output, languageText(lang).goodbye)
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1", "r", "refresh", "刷新":
			continue
		case "2", "s", "start", "启动服务":
			if prefs.Core != "local" {
				fmt.Fprintln(output, localized(lang, "Online core cannot start a remote process. Switch to local core to start this machine's service.", "在线核心不能在远端启动进程。切换到本地核心以启动本机服务。"))
				continue
			}
			if statusErr == nil {
				fmt.Fprintln(output, localized(lang, "Service is already running.", "服务已经在运行。"))
				continue
			}
			if prefs.ServerExecutable == "" {
				fmt.Fprintln(errorsOut, localized(lang, "Set the aries-server path in Core selection before starting.", "请先在核心选择中设置 aries-server 程序路径。"))
				continue
			}
			endpoint, tokenFile, connectionErr := localConnection(prefs.ConfigPath)
			if connectionErr != nil {
				fmt.Fprintf(errorsOut, "%s: %v\n", localized(lang, "Invalid local core config", "本地核心配置无效"), connectionErr)
				continue
			}
			o.endpoint, o.token = endpoint, tokenFile
			logPath := filepath.Join(filepath.Dir(prefs.ConfigPath), "logs", "server.log")
			pid, startErr := startDetachedServer(prefs.ServerExecutable, prefs.ConfigPath, logPath)
			if startErr != nil {
				fmt.Fprintf(errorsOut, "%s: %v\n", localized(lang, "Could not start service", "无法启动服务"), startErr)
				continue
			}
			if waitErr := waitForAdmin(o, 8*time.Second); waitErr != nil {
				fmt.Fprintf(errorsOut, "%s (PID %d). %s: %s\n", localized(lang, "Process launched", "进程已启动"), pid, localized(lang, "Check server log", "请检查服务日志"), logPath)
			} else {
				fmt.Fprintf(output, "%s (PID %d)\n", languageText(lang).serverStarted, pid)
			}
		case "3", "t", "stop", "shutdown", "终止服务":
			if statusErr != nil {
				fmt.Fprintln(output, localized(lang, "Service is not connected; nothing to stop.", "当前未连接服务，无需终止。"))
				continue
			}
			var result, commandErrors strings.Builder
			if err := executeCLI(commandArgs(o, []string{"server", "shutdown"}), reader, &result, &commandErrors); err != nil {
				fmt.Fprintf(errorsOut, "%s: %s\n", languageText(lang).commandError, strings.TrimSpace(commandErrors.String()))
			} else {
				renderCommandResult(output, []byte(result.String()), lang)
				fmt.Fprintln(output, localized(lang, "Shutdown was requested through the authenticated admin API.", "已通过认证管理 API 请求关闭服务。"))
			}
		case "4", "c", "core", "核心选择":
			prefs, o, err = chooseCore(prefs, o, reader, output, lang, rawInput)
			if err != nil {
				fmt.Fprintf(errorsOut, "%s: %v\n", languageText(lang).setupFailed, err)
				continue
			}
			_ = saveUIPreferences(prefsPath, prefs)
		case "5", "settings", "设置":
			if err := runSettingsMenu(&o, &prefs, reader, output, errorsOut, lang, rawInput); err != nil {
				fmt.Fprintf(errorsOut, "%s: %v\n", localized(lang, "Settings failed", "设置失败"), err)
			}
			_ = saveUIPreferences(prefsPath, prefs)
		case "6", "language", "lang", "语言":
			lang, err = promptLanguage(reader, output, lang, rawInput)
			if err == nil {
				prefs.Language = string(lang)
				_ = saveUIPreferences(prefsPath, prefs)
				fmt.Fprintln(output, languageText(lang).languageChanged)
			}
		case "7", "q", "quit", "exit", "退出":
			fmt.Fprintln(output, languageText(lang).goodbye)
			return nil
		case "h", "help", "帮助":
			printLocalizedHelp(output, lang)
		default:
			fmt.Fprintln(output, languageText(lang).invalidInput)
		}
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(output, languageText(lang).goodbye)
			return nil
		}
	}
}

// readMenuAction reads one dashboard action. In a raw terminal it consumes
// escape sequences directly, so users can move the selection with ↑/↓ and
// press Enter without typing a number. A non-TTY (tests, pipes, redirected
// input) falls back to the existing line reader and accepts the documented
// command aliases, including numeric aliases for compatibility.
func beginMenuKeyboard(rawInput io.Reader, output io.Writer) (bool, func()) {
	if !interactiveTerminal(rawInput, output) {
		return false, nil
	}
	restore, err := enterRawTerminal(rawInput)
	if err != nil {
		return false, nil
	}
	return true, restore
}

// interactiveTerminal detects terminal file descriptors independently from
// TERM. Minimal SSH clients often set TERM=dumb, but their console can still
// send arrow-key sequences and accept raw keyboard input.
func interactiveTerminal(input io.Reader, output io.Writer) bool {
	inputFile, inputOK := input.(*os.File)
	outputFile, outputOK := output.(*os.File)
	if !inputOK || !outputOK {
		return false
	}
	inputInfo, inputErr := inputFile.Stat()
	outputInfo, outputErr := outputFile.Stat()
	return inputErr == nil && outputErr == nil &&
		inputInfo.Mode()&os.ModeCharDevice != 0 && outputInfo.Mode()&os.ModeCharDevice != 0
}

func readMenuAction(reader *bufio.Reader, _ io.Reader, selected, itemCount int, keyboard bool) (string, int, error) {
	if !keyboard {
		choice, err := readInputLine(reader)
		return strings.TrimSpace(choice), selected, err
	}
	if itemCount < 1 {
		return "", selected, errors.New("menu has no items")
	}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", selected, err
		}
		if b == 0x1b {
			// Terminal arrows arrive as ESC [ A/B (or ESC O A/B). ESC by
			// itself is ignored; q, Ctrl+C, or Back are the explicit exit keys.
			next, readErr := reader.ReadByte()
			if readErr != nil {
				return "", selected, readErr
			}
			if next == '[' || next == 'O' {
				arrow, arrowErr := reader.ReadByte()
				if arrowErr != nil {
					return "", selected, arrowErr
				}
				switch arrow {
				case 'A':
					selected = (selected + itemCount - 1) % itemCount
				case 'B':
					selected = (selected + 1) % itemCount
				}
				return "navigate", selected, nil
			}
			b = next
		}
		switch b {
		case '\r', '\n':
			return strconv.Itoa(selected + 1), selected, nil
		case 0x03, 0x04, 'q', 'Q':
			return "q", selected, nil
		case 'h', 'H':
			return "help", selected, nil
		default:
			// Ignore stray bytes (including function-key prefixes) and keep
			// waiting for a complete action.
		}
	}
}

// selectMenuOption is the shared bilingual menu picker used by the dashboard
// submenus and the first-run wizard. It returns a zero-based choice, or -1
// when the user cancels with q or Back. In a TTY it uses arrows and
// Enter; non-TTY callers retain line input compatibility.
func selectMenuOption(reader *bufio.Reader, rawInput io.Reader, output io.Writer, title string, choices []string, selected int, lang uiLanguage) (int, error) {
	if len(choices) == 0 {
		return -1, errors.New("menu has no choices")
	}
	if selected < 0 || selected >= len(choices) {
		selected = 0
	}
	keyboard, restore := beginMenuKeyboard(rawInput, output)
	if restore != nil {
		defer restore()
	}
	for {
		drawChoiceMenu(output, title, choices, selected, keyboard, lang)
		action, next, err := readMenuAction(reader, rawInput, selected, len(choices), keyboard)
		if err != nil {
			return -1, err
		}
		if keyboard && action == "navigate" {
			selected = next
			continue
		}
		if keyboard {
			if action == "q" {
				return -1, nil
			}
			if action == "help" {
				continue
			}
			return selected, nil
		}
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "q", "quit", "exit", "b", "back", "esc", "escape", "退出", "返回":
			return -1, nil
		}
		if index, parseErr := strconv.Atoi(action); parseErr == nil {
			if index >= 1 && index <= len(choices) {
				return index - 1, nil
			}
		}
		for i, choice := range choices {
			if strings.EqualFold(strings.TrimSpace(choice), strings.TrimSpace(action)) {
				return i, nil
			}
		}
		fmt.Fprintln(output, languageText(lang).invalidInput)
	}
}

// chooseMenuItem is the concise wrapper used by UI startup flows.
func chooseMenuItem(reader *bufio.Reader, rawInput io.Reader, output io.Writer, title string, choices []string, selected int, lang uiLanguage) (int, error) {
	return selectMenuOption(reader, rawInput, output, title, choices, selected, lang)
}

func drawChoiceMenu(output io.Writer, title string, choices []string, selected int, keyboard bool, lang uiLanguage) {
	if interactiveOutput(output) {
		fmt.Fprint(output, "\x1b[2J\x1b[H")
	}
	width := tuiWidth(output)
	cyan, purple, _, _, dim, reset := tuiPalette(output)
	drawSectionHeader(output, width, purple, reset, fitTUI(title, maxInt(1, width-8)))
	for i, choice := range choices {
		marker := ""
		label := choice
		if keyboard {
			marker = "  "
			if i == selected {
				marker = "❯ "
			}
		} else {
			marker = fmt.Sprintf("[%02d] ", i+1)
		}
		lineWidth := width - 2
		labelWidth := lineWidth - tuiDisplayWidth(marker)
		if labelWidth < 0 {
			labelWidth = 0
		}
		color := cyan
		if i == selected && keyboard && interactiveOutput(output) {
			color = "\x1b[1;7;37m"
		}
		fmt.Fprintf(output, "%s│%s%s%s%s│%s\n", cyan, color, marker, fitTUI(label, labelWidth), reset, cyan)
	}
	drawSectionFooter(output, width, purple, reset)
	if keyboard {
		fmt.Fprintf(output, "%s  %s%s\n", dim, fitTUI(localized(lang, "↑/↓ navigate · Enter select · q or Ctrl+C back", "↑/↓ 移动 · Enter 确认 · q 或 Ctrl+C 返回"), width-4), reset)
	} else {
		fmt.Fprintf(output, "%s  %s%s\n", dim, fitTUI(localized(lang, "Type a choice label or its compatibility number · q back", "输入选项名称或兼容数字 · q 返回"), width-4), reset)
		fmt.Fprintf(output, "%s: ", localized(lang, "Choose", "请选择"))
	}
}

func chooseCore(prefs uiPreferences, o options, reader *bufio.Reader, output io.Writer, lang uiLanguage, rawInputs ...io.Reader) (uiPreferences, options, error) {
	var rawInput io.Reader
	if len(rawInputs) > 0 {
		rawInput = rawInputs[0]
	}
	selected := 0
	if prefs.Core == "online" {
		selected = 1
	}
	choice, err := selectMenuOption(reader, rawInput, output, localized(lang, "Select core", "选择核心"), []string{
		coreLabel("local", lang), coreLabel("online", lang),
	}, selected, lang)
	if err != nil {
		return prefs, o, err
	}
	switch choice {
	case -1:
		return prefs, o, nil
	case 0:
		prefs, err = selectLocalCore(prefs, reader, output, lang)
		if err == nil {
			o.endpoint, o.token = "", ""
			o.endpoint, o.token, err = localConnection(prefs.ConfigPath)
		}
	case 1:
		prefs, o, err = selectOnlineCore(prefs, o, reader, output, lang)
	default:
		return prefs, o, errors.New(languageText(lang).invalidInput)
	}
	return prefs, o, err
}

func fetchAdminStatus(o options) (map[string]any, error) {
	if o.endpoint == "" || o.token == "" {
		return nil, errors.New("admin endpoint and token file are not set")
	}
	api, err := client.New(o.endpoint, o.token, o.timeout)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	body, err := api.Get(ctx, "/api/v1/admin/status")
	if err != nil {
		return nil, err
	}
	var status map[string]any
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, err
	}
	return status, nil
}

func drawMainMenu(output io.Writer, o options, prefs uiPreferences, lang uiLanguage, status map[string]any, connected bool, selected int, keyboard bool) {
	if interactiveOutput(output) {
		fmt.Fprint(output, "\x1b[2J\x1b[H")
	}
	cyan, purple, green, yellow, dim, reset := tuiPalette(output)
	text := languageText(lang)
	core := coreLabel(prefs.Core, lang)
	state := localized(lang, "○ OFFLINE", "○ 离线")
	stateColor := yellow
	if connected {
		state = localized(lang, "● CONNECTED", "● 已连接")
		stateColor = green
	}
	endpoint := o.endpoint
	if endpoint == "" {
		endpoint = "—"
	}
	panelWidth := tuiWidth(output)
	drawTUIHeader(output, panelWidth, cyan, green, dim, reset, "◈  "+text.title, text.subtitle, localized(lang, "v1 CONTROL CENTER", "v1 控制中心"))

	left, right := dashboardCards(status, lang, connected, endpoint, core, state)
	drawTwoCards(output, panelWidth, left, right, cyan, stateColor, reset)
	if !connected {
		fmt.Fprintf(output, "%s│ %s │%s\n", yellow, fitTUI(localized(lang, "Admin API is not reachable. Choose Core selection or check the default token path.", "管理 API 尚未连接。请进入核心选择，或检查默认令牌路径."), panelWidth-4), reset)
	}

	drawSectionHeader(output, panelWidth, purple, reset, localized(lang, "OPERATIONS", "服务操作"))
	menuLine(output, panelWidth, "1", localized(lang, "Refresh status", "刷新状态"), localized(lang, "Poll the authenticated node status", "读取认证后的节点状态"), cyan, reset, selected == 0, keyboard)
	startLabel := localized(lang, "Start service", "启动服务")
	if prefs.Core != "local" {
		startLabel = localized(lang, "Start service (local core only)", "启动服务（仅本地核心）")
	}
	menuLine(output, panelWidth, "2", startLabel, localized(lang, "Launch a detached local server process", "脱离 CLI 生命周期启动本地服务"), cyan, reset, selected == 1, keyboard)
	menuLine(output, panelWidth, "3", localized(lang, "Stop service", "终止服务"), localized(lang, "Request graceful shutdown through admin API", "通过管理 API 请求优雅停止"), cyan, reset, selected == 2, keyboard)
	drawSectionFooter(output, panelWidth, purple, reset)
	drawSectionHeader(output, panelWidth, purple, reset, localized(lang, "CONFIGURATION", "配置与会话"))
	menuLine(output, panelWidth, "4", localized(lang, "Core selection", "核心选择"), localized(lang, "Switch local core or token-authenticated online core", "切换本地核心或令牌认证的在线核心"), cyan, reset, selected == 3, keyboard)
	menuLine(output, panelWidth, "5", localized(lang, "Settings", "设置"), localized(lang, "Edit the documented server configuration", "编辑交接文档中的服务配置"), cyan, reset, selected == 4, keyboard)
	menuLine(output, panelWidth, "6", localized(lang, "Language / 语言", "语言 / Language"), localized(lang, "Switch Chinese or English interface", "切换中文或英文界面"), cyan, reset, selected == 5, keyboard)
	menuLine(output, panelWidth, "7", localized(lang, "Exit CLI (service stays in background)", "结束 CLI（服务继续在后台运行）"), localized(lang, "Leave the server process running", "服务继续在后台运行"), cyan, reset, selected == 6, keyboard)
	drawSectionFooter(output, panelWidth, purple, reset)
	if keyboard {
		fmt.Fprintf(output, "%s  %s%s\n", dim, fitTUI(localized(lang, "↑/↓ navigate · Enter select · q or Ctrl+C exit · h help", "↑/↓ 移动 · Enter 选择 · q 或 Ctrl+C 退出 · h 帮助"), panelWidth-4), reset)
	} else {
		fmt.Fprintf(output, "%s  %s%s  %s\n", dim, fitTUI(localized(lang, "1-7 choose · h help · Ctrl+C leaves service running", "1-7 选择 · h 帮助 · Ctrl+C 不会停止服务"), panelWidth-24), reset, localized(lang, "Enter choice", "请输入选项"))
		fmt.Fprintf(output, "%s%s%s: ", green, text.choose, reset)
	}
}

func drawTUIHeader(output io.Writer, width int, border, accent, dim, reset, title, subtitle, tag string) {
	inner := width - 2
	fmt.Fprintf(output, "%s╭%s╮%s\n", border, strings.Repeat("─", inner), reset)
	line := title + "  " + tag
	fmt.Fprintf(output, "%s│%s│%s\n", border, fitTUI(line, inner), reset)
	fmt.Fprintf(output, "%s│%s│%s\n", border, fitTUI(subtitle, inner), reset)
	fmt.Fprintf(output, "%s╰%s╯%s\n", border, strings.Repeat("─", inner), reset)
}

func drawSectionHeader(output io.Writer, outer int, color, reset, title string) {
	prefix := "╭─ " + title + " "
	remaining := outer - tuiDisplayWidth(prefix) - 1
	if remaining < 1 {
		remaining = 1
	}
	fmt.Fprintf(output, "\n%s%s%s╮%s\n", color, prefix, strings.Repeat("─", remaining), reset)
}

func drawSectionFooter(output io.Writer, outer int, color, reset string) {
	fmt.Fprintf(output, "%s╰%s╯%s\n", color, strings.Repeat("─", maxInt(1, outer-2)), reset)
}

func tuiPalette(output io.Writer) (cyan, purple, green, yellow, dim, reset string) {
	if !interactiveOutput(output) {
		return "", "", "", "", "", ""
	}
	return "\x1b[36m", "\x1b[35m", "\x1b[32m", "\x1b[33m", "\x1b[2m", "\x1b[0m"
}

func menuLine(output io.Writer, outer int, number, label, hint, accent, reset string, selected, keyboard bool) {
	dim := ""
	if interactiveOutput(output) {
		dim = "\x1b[2m"
	}
	marker := ""
	if keyboard {
		marker = "  "
		if selected {
			marker = "❯ "
		}
	} else {
		marker = "[" + number + "] "
	}
	available := outer - 2 - tuiDisplayWidth(marker) - 1
	if available < 4 {
		available = 4
	}
	labelWidth := available * 56 / 100
	hintWidth := available - labelWidth
	markerColor := ""
	if selected && keyboard && interactiveOutput(output) {
		markerColor = "\x1b[1;37m"
	}
	fmt.Fprintf(output, "%s│%s%s%s%s %s%s%s│%s\n", accent, reset, markerColor, marker, reset, fitTUI(label, labelWidth), dim, fitTUI(hint, hintWidth), reset+accent)
}

func dashboardCards(status map[string]any, lang uiLanguage, connected bool, endpoint, core, state string) ([]string, []string) {
	listener := func(key string) string {
		m, _ := status[key].(map[string]any)
		return valueString(m["address"])
	}
	if !connected {
		status = map[string]any{}
	}
	deviceText := valueString(status["connected_devices"])
	if deviceText == "" || deviceText == "<nil>" {
		deviceText = localized(lang, "not tracked", "暂未追踪")
	}
	storage := localizeState(valueString(status["storage_state"]), lang)
	if storage == "" {
		storage = localized(lang, "—", "—")
	}
	left := []string{
		localized(lang, "SERVICE", "服务状态"),
		state,
		localized(lang, "Public  ", "公开    ") + listener("public_listener"),
		localized(lang, "Admin   ", "管理    ") + listener("admin_listener"),
		localized(lang, "Storage ", "存储    ") + storage,
		localized(lang, "Devices ", "设备    ") + deviceText,
	}
	nodeID := valueString(status["node_id"])
	if nodeID == "" {
		nodeID = "—"
	}
	serverCode := valueString(status["server_code"])
	if serverCode == "" {
		serverCode = "—"
	}
	uptime := formatUptime(status["uptime_seconds"], lang)
	if !connected {
		uptime = "—"
	}
	right := []string{
		localized(lang, "CORE PROFILE", "核心配置"),
		core,
		localized(lang, "Endpoint", "管理端点") + "  " + endpoint,
		localized(lang, "Node ID ", "节点 ID ") + "  " + nodeID,
		localized(lang, "Code    ", "服务器号") + "  " + serverCode,
		localized(lang, "Uptime  ", "运行时间") + "  " + uptime,
	}
	return left, right
}

func drawTwoCards(output io.Writer, width int, left, right []string, border, stateColor, reset string) {
	cardOuter := (width - 2) / 2
	cellWidth := cardOuter - 4
	cardLine := strings.Repeat("─", cardOuter-2)
	fmt.Fprintf(output, "%s╭%s╮  ╭%s╮%s\n", border, cardLine, cardLine, reset)
	for i := 0; i < 6; i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		color := border
		if i == 1 {
			color = stateColor
		}
		fmt.Fprintf(output, "%s│%s %s %s│  %s│%s %s %s│%s\n", border, color, fitTUI(l, cellWidth), reset, border, color, fitTUI(r, cellWidth), reset, border)
	}
	fmt.Fprintf(output, "%s╰%s╯  ╰%s╯%s\n", border, cardLine, cardLine, reset)
}

func fitTUI(value string, width int) string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " ")
	runes := []rune(value)
	used := 0
	cut := len(runes)
	for i, r := range runes {
		runeWidth := tuiRuneWidth(r)
		if used+runeWidth > width {
			cut = i
			break
		}
		used += runeWidth
	}
	if cut < len(runes) {
		if width >= 1 {
			value = string(runes[:cut]) + "…"
			used = tuiDisplayWidth(value)
		} else {
			value = ""
			used = 0
		}
	}
	return value + strings.Repeat(" ", maxInt(0, width-used))
}

// tuiWidth follows the actual console width, with a small lower bound to keep
// box-drawing arithmetic valid on unusually narrow terminal windows.
func tuiWidth(output io.Writer) int {
	width := terminalWidth(output)
	if width < 24 {
		return 24
	}
	if width > 160 {
		return 160
	}
	return width
}

func tuiDisplayWidth(value string) int {
	width := 0
	for _, r := range value {
		width += tuiRuneWidth(r)
	}
	return width
}

func tuiRuneWidth(r rune) int {
	if r == '\t' {
		return 4
	}
	// East Asian wide/full-width ranges used by Chinese labels and symbols.
	if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a || (r >= 0x2e80 && r <= 0xa4cf) || (r >= 0xac00 && r <= 0xd7a3) || (r >= 0xf900 && r <= 0xfaff) || (r >= 0xfe10 && r <= 0xfe6f) || (r >= 0xff01 && r <= 0xff60) || (r >= 0xffe0 && r <= 0xffe6) || (r >= 0x20000 && r <= 0x3fffd)) {
		return 2
	}
	return 1
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func printDashboardStatus(output io.Writer, status map[string]any, lang uiLanguage) {
	listener := func(key string) string {
		m, _ := status[key].(map[string]any)
		return valueString(m["address"])
	}
	devices := status["connected_devices"]
	deviceText := valueString(devices)
	if devices == nil {
		deviceText = localized(lang, "not tracked", "暂未追踪")
	}
	storage := valueString(status["storage_state"])
	fmt.Fprintf(output, "  %s: %s   %s: %s\n", localized(lang, "Node", "节点"), valueString(status["node_id"]), localized(lang, "Server code", "服务器号"), valueString(status["server_code"]))
	fmt.Fprintf(output, "  %s: %s   %s: %s\n", localized(lang, "Public listener", "公开监听"), listener("public_listener"), localized(lang, "Admin listener", "管理监听"), listener("admin_listener"))
	fmt.Fprintf(output, "  %s: %s   %s: %s   %s: %s\n", localized(lang, "Devices", "在线设备"), deviceText, localized(lang, "Storage", "存储"), localizeState(storage, lang), localized(lang, "Uptime", "运行时间"), formatUptime(status["uptime_seconds"], lang))
}

func formatUptime(value any, lang uiLanguage) string {
	seconds, _ := strconv.ParseInt(valueString(value), 10, 64)
	if seconds < 0 {
		seconds = 0
	}
	d := time.Duration(seconds) * time.Second
	if lang == langChinese {
		return fmt.Sprintf("%d天 %02d:%02d:%02d", int64(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60, int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dd %02d:%02d:%02d", int64(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60, int(d.Seconds())%60)
}

func localizeState(state string, lang uiLanguage) string {
	if lang != langChinese {
		return state
	}
	switch state {
	case "available":
		return "可用"
	case "degraded":
		return "降级"
	case "unavailable":
		return "不可用"
	case "disabled":
		return "已关闭"
	case "not_implemented":
		return "尚未实现"
	default:
		return state
	}
}

func promptLanguage(reader *bufio.Reader, output io.Writer, current uiLanguage, rawInputs ...io.Reader) (uiLanguage, error) {
	var rawInput io.Reader
	if len(rawInputs) > 0 {
		rawInput = rawInputs[0]
	}
	selected := 0
	if current == langChinese {
		selected = 1
	}
	choice, err := selectMenuOption(reader, rawInput, output, languageText(current).languagePrompt, []string{
		localized(current, "English", "English"), localized(current, "Chinese", "中文"),
	}, selected, current)
	if err != nil {
		return current, err
	}
	switch choice {
	case -1:
		return current, nil
	case 1:
		return langChinese, nil
	case 0:
		return langEnglish, nil
	default:
		return current, errors.New(languageText(current).invalidInput)
	}
}

func localized(lang uiLanguage, english, chinese string) string {
	if lang == langChinese {
		return chinese
	}
	return english
}

type settingInfo struct {
	Key, Kind, En, Zh string
}

var uiSettings = []settingInfo{
	{"public_listen", "string", "Public service listen address", "公开服务监听地址"},
	{"admin_listen", "string", "Admin API listen address", "管理 API 监听地址"},
	{"data_dir", "string", "Data directory", "数据目录"},
	{"admin_token_file", "string", "Admin token file path (never displays token contents)", "管理员令牌文件路径（不会显示令牌内容）"},
	{"max_storage_bytes", "integer", "Maximum storage (GB; 0 = unlimited)", "最大存储容量（GB；0 表示不限制）"},
	{"allow_insecure_loopback", "boolean", "Allow plain HTTP on loopback for development", "允许开发环境在本机回环地址使用 HTTP"},
	{"peer_relay_enabled", "boolean", "Peer relay flag (not implemented in this build)", "节点中继开关（当前版本尚未实现互联）"},
	{"file_storage_enabled", "boolean", "Enable file storage", "启用文件存储"},
	{"group_quota_bytes", "integer", "Per-group storage quota (GB)", "每个小组的存储配额（GB）"},
	{"quota_bytes_per_member", "integer", "Per-member quota (GB); 0 uses group quota", "每位成员的配额（GB）；0 使用小组配额"},
	{"max_file_bytes", "integer", "Maximum file size (GB; 0 = unlimited)", "单个文件大小上限（GB；0 表示不限制）"},
	{"max_file_ttl_seconds", "integer", "Maximum file lifetime seconds; 0 = unlimited", "文件最大保留秒数；0 表示不限制"},
}

func runSettingsMenu(o *options, prefs *uiPreferences, reader *bufio.Reader, output, errorsOut io.Writer, lang uiLanguage, rawInputs ...io.Reader) error {
	var rawInput io.Reader
	if len(rawInputs) > 0 {
		rawInput = rawInputs[0]
	}
	selected := 0
	for {
		config, err := readSettingsConfig(*o, *prefs)
		if err != nil {
			fmt.Fprintf(errorsOut, "%s: %v\n", languageText(lang).requestFailed, err)
			return err
		}
		choices := make([]string, 0, len(uiSettings)+1)
		for _, field := range uiSettings {
			label := field.En
			if lang == langChinese {
				label = field.Zh
			}
			value := formatSettingValue(field, config[field.Key], lang)
			choices = append(choices, label+"  ·  "+value)
		}
		choices = append(choices, localized(lang, "Back", "返回"))
		if selected >= len(choices) {
			selected = len(choices) - 1
		}
		choice, chooseErr := selectMenuOption(reader, rawInput, output, localized(lang, "SETTINGS", "设置"), choices, selected, lang)
		if errors.Is(chooseErr, io.EOF) {
			return nil
		}
		if chooseErr != nil {
			return chooseErr
		}
		if choice < 0 || choice == len(uiSettings) {
			return nil
		}
		selected = choice
		field := uiSettings[choice]
		label := field.En
		if lang == langChinese {
			label = field.Zh
		}
		var newValue string
		var updated json.RawMessage
		inputEnded := false
		if field.Kind == "boolean" {
			var current bool
			_ = json.Unmarshal(config[field.Key], &current)
			booleanChoice := 1
			if current {
				booleanChoice = 0
			}
			boolIndex, boolErr := selectMenuOption(reader, rawInput, output, label, []string{
				localized(lang, "Enabled", "启用"), localized(lang, "Disabled", "禁用"),
			}, booleanChoice, lang)
			if boolErr != nil {
				return boolErr
			}
			if boolIndex < 0 {
				continue
			}
			newValue = strconv.FormatBool(boolIndex == 0)
			updated, boolErr = parseSettingInput(field, newValue)
			if boolErr != nil {
				fmt.Fprintf(errorsOut, "%s: %v\n", localized(lang, "Invalid value", "无效的值"), boolErr)
				continue
			}
		} else {
			defaultValue := settingInputDefault(field, config[field.Key])
			var inputErr error
			newValue, inputErr = askDefault(reader, output, localized(lang, "New value for "+label, label+"的新值"), defaultValue)
			if inputErr != nil && newValue == "" {
				return inputErr
			}
			inputEnded = errors.Is(inputErr, io.EOF)
			var setErr error
			updated, setErr = parseSettingInput(field, newValue)
			if setErr != nil {
				fmt.Fprintf(errorsOut, "%s: %v\n", localized(lang, "Invalid value", "无效的值"), setErr)
				continue
			}
		}
		if field.Key == "admin_listen" {
			var address string
			_ = json.Unmarshal(updated, &address)
			if !isLoopbackListen(address) {
				fmt.Fprintln(errorsOut, localized(lang, "The current server has no direct TLS admin listener. Keep admin_listen on loopback and use a TLS reverse proxy for remote access.", "当前服务没有内置 TLS 管理监听器。请将 admin_listen 保持在本机回环地址，远程访问通过 TLS 反向代理。"))
				continue
			}
		}
		config[field.Key] = updated
		if prefs.Core == "local" {
			if err = saveLocalSettings(prefs.ConfigPath, config); err == nil {
				fmt.Fprintln(output, localized(lang, "Saved to local config. Restart the service for the change to take effect.", "已写入本地配置。请重启服务使设置生效。"))
			}
		} else {
			err = putRemoteSettings(*o, config)
			if err == nil {
				fmt.Fprintln(output, localized(lang, "Configuration saved by the authenticated admin API. Listener, data, and token path changes require a service restart.", "已通过认证管理 API 保存配置。监听地址、数据目录和令牌路径变更需要重启服务。"))
			}
		}
		if err != nil {
			fmt.Fprintf(errorsOut, "%s: %v\n", localized(lang, "Could not save setting", "无法保存设置"), err)
		}
		if inputEnded {
			return nil
		}
	}
}

var byteSettingKeys = map[string]bool{
	"max_storage_bytes":      true,
	"group_quota_bytes":      true,
	"quota_bytes_per_member": true,
	"max_file_bytes":         true,
}

func formatSettingValue(field settingInfo, raw json.RawMessage, lang uiLanguage) string {
	if field.Kind == "integer" {
		n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err == nil {
			if byteSettingKeys[field.Key] {
				return formatBytesGB(n, lang)
			}
			return strconv.FormatInt(n, 10)
		}
	}
	var value any
	if json.Unmarshal(raw, &value) == nil {
		if value == nil {
			return "—"
		}
		return fmt.Sprint(value)
	}
	return strings.TrimSpace(string(raw))
}

func formatBytesGB(value int64, lang uiLanguage) string {
	if value < 0 {
		return "—"
	}
	const gb int64 = 1024 * 1024 * 1024
	whole := value / gb
	// Round to two decimal places using integer arithmetic so large byte
	// counts never pass through float formatting (and never use exponents).
	frac := ((value%gb)*100 + gb/2) / gb
	if frac == 100 {
		whole++
		frac = 0
	}
	result := fmt.Sprintf("%d", whole)
	if frac > 0 {
		result = fmt.Sprintf("%d.%02d", whole, frac)
		result = strings.TrimRight(strings.TrimRight(result, "0"), ".")
	}
	if lang == langChinese {
		return result + " GB"
	}
	return result + " GB"
}

func readSettingsConfig(o options, prefs uiPreferences) (map[string]json.RawMessage, error) {
	var body json.RawMessage
	if prefs.Core == "local" {
		config, err := kernel.LoadConfig(prefs.ConfigPath)
		if err != nil {
			return nil, err
		}
		body, err = json.Marshal(config)
		if err != nil {
			return nil, err
		}
	} else {
		api, err := client.New(o.endpoint, o.token, o.timeout)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
		defer cancel()
		body, err = api.Get(ctx, "/api/v1/admin/config")
		if err != nil {
			return nil, err
		}
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	return config, nil
}

func typedSettingValue(kind, value string) (json.RawMessage, error) {
	switch kind {
	case "integer":
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil || n < 0 {
			return nil, errors.New("enter a non-negative integer")
		}
		return json.Marshal(n)
	case "boolean":
		b, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return nil, errors.New("enter true or false")
		}
		return json.Marshal(b)
	default:
		if strings.TrimSpace(value) == "" {
			return nil, errors.New("value cannot be empty")
		}
		return json.Marshal(strings.TrimSpace(value))
	}
}

func saveLocalSettings(path string, raw map[string]json.RawMessage) error {
	body, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	var config kernel.Config
	if err := json.Unmarshal(body, &config); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if config.AdminTokenFile != "" {
		tokenPath := config.AdminTokenFile
		if !filepath.IsAbs(tokenPath) {
			tokenPath = filepath.Join(filepath.Dir(path), tokenPath)
		}
		if _, err := client.ReadToken(tokenPath); err != nil {
			return fmt.Errorf("admin_token_file must point to an existing protected token file: %w", err)
		}
	}
	formatted, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, formatted, 0600)
}

func putRemoteSettings(o options, config map[string]json.RawMessage) error {
	body, err := json.Marshal(config)
	if err != nil {
		return err
	}
	api, err := client.New(o.endpoint, o.token, o.timeout)
	if err != nil {
		return err
	}
	key, err := newIdempotencyKey()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	_, err = api.Put(ctx, "/api/v1/admin/config", body, key)
	return err
}
