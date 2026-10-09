package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aries.local/aries/internal/client"
	"aries.local/aries/internal/kernel"
)

type uiLanguage string

const (
	langEnglish uiLanguage = "en"
	langChinese uiLanguage = "zh"
)

type uiPreferences struct {
	Language         string `json:"language"`
	Core             string `json:"core"`
	Endpoint         string `json:"endpoint,omitempty"`
	TokenFile        string `json:"token_file,omitempty"`
	ServerExecutable string `json:"server_executable,omitempty"`
	ConfigPath       string `json:"config_path,omitempty"`
}

type uiText struct {
	title, subtitle, endpoint, connected, offline                                 string
	firstRun, setupChoice, connectChoice, offlineChoice, quitChoice               string
	choose, languagePrompt, chinese, english, languageChanged                     string
	setupTitle, installDir, publicListen, adminListen, publicListenHint           string
	launchNow, setupCreated, serverStarted, serverMissing, serverStartFailed      string
	configPath, tokenPath, logPath, setupFailed                                   string
	existingTitle, endpointPrompt, tokenPrompt, connectionFailed                  string
	welcome, helpHint, prompt, goodbye, invalidInput, parseError                  string
	noCommands, commandError, requestFailed, unknownLanguage                      string
	noColorHint, commandsTitle, permission, usage, connectedDevices, notSupported string
	footer, offlineHelp                                                           string
}

func normalizeLanguage(value string) (uiLanguage, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "zh", "zh-cn", "zh-hans", "chinese", "中文":
		return langChinese, nil
	case "en", "en-us", "en-gb", "english", "英文":
		return langEnglish, nil
	default:
		return "", fmt.Errorf("--language must be `en` or `zh`")
	}
}

func languageText(lang uiLanguage) uiText {
	if lang == langChinese {
		return uiText{
			title: "Aries 服务管理", subtitle: "服务端交互控制台",
			endpoint: "管理端点", connected: "已连接", offline: "离线模式",
			firstRun: "首次部署 / 连接设置", setupChoice: "创建并启动本机服务", connectChoice: "连接已有服务", offlineChoice: "稍后设置，先进入离线帮助", quitChoice: "退出",
			choose: "请选择", languagePrompt: "选择界面语言 / Select interface language", chinese: "中文", english: "English", languageChanged: "界面语言已切换为中文。",
			setupTitle: "首次部署向导", installDir: "安装目录", publicListen: "公开服务监听地址", adminListen: "本机管理监听地址", publicListenHint: "默认仅本机可访问；如需局域网访问可用 0.0.0.0:8787，并配置防火墙/TLS 反向代理。",
			launchNow: "现在启动服务？", setupCreated: "配置和受保护的管理员令牌已创建。令牌内容不会显示。", serverStarted: "服务已启动", serverMissing: "没有找到同目录的 aries-server，可用下方命令手动启动。", serverStartFailed: "启动失败；请检查日志并按下方命令手动启动。",
			configPath: "配置文件", tokenPath: "令牌文件", logPath: "服务日志", setupFailed: "部署设置失败",
			existingTitle: "连接已有服务", endpointPrompt: "管理 API 地址", tokenPrompt: "管理员令牌文件路径", connectionFailed: "连接失败",
			welcome: "输入 help 查看命令；输入 language en 切换英文，输入 quit 退出。", helpHint: "Aries 管理命令", prompt: "aries", goodbye: "会话已结束。", invalidInput: "无效选项，请重试。", parseError: "命令引号不匹配。",
			noCommands: "当前没有可用命令。", commandError: "命令失败", requestFailed: "连接不可用；请检查端点和令牌文件。", unknownLanguage: "语言仅支持 zh 或 en。",
			noColorHint: "提示：输入 help 查看命令，language en|zh 切换语言。", commandsTitle: "命令", permission: "权限", usage: "用法", connectedDevices: "在线设备", notSupported: "暂不支持",
			footer: "Enter 执行 · help 帮助 · language zh|en 切换语言 · quit 退出", offlineHelp: "离线模式下可查看帮助；远程管理命令需要先连接服务器。",
		}
	}
	return uiText{
		title: "Aries Service Control", subtitle: "Interactive management terminal",
		endpoint: "Admin endpoint", connected: "connected", offline: "offline",
		firstRun: "First deployment / connection setup", setupChoice: "Set up and start a local server", connectChoice: "Connect to an existing server", offlineChoice: "Continue offline for help", quitChoice: "Quit",
		choose: "Choose", languagePrompt: "Select interface language / 选择界面语言", chinese: "中文", english: "English", languageChanged: "Interface language changed to English.",
		setupTitle: "First deployment wizard", installDir: "Installation directory", publicListen: "Public service listen address", adminListen: "Local admin listen address", publicListenHint: "Loopback is the safe default. For LAN access use 0.0.0.0:8787 with firewall rules and a TLS reverse proxy.",
		launchNow: "Start the server now?", setupCreated: "Config and protected admin token created. The token value was not displayed.", serverStarted: "Server started", serverMissing: "No sibling aries-server executable was found. Start it with the command below.", serverStartFailed: "Could not start the server; check the log and use the command below.",
		configPath: "Config file", tokenPath: "Token file", logPath: "Server log", setupFailed: "Deployment setup failed",
		existingTitle: "Connect to an existing server", endpointPrompt: "Admin API endpoint", tokenPrompt: "Admin token file path", connectionFailed: "Connection failed",
		welcome: "Type help for commands; use language zh to switch to Chinese, or quit to exit.", helpHint: "Aries management commands", prompt: "aries", goodbye: "Session ended.", invalidInput: "Invalid choice. Try again.", parseError: "Unmatched command quote.",
		noCommands: "No commands are available.", commandError: "Command failed", requestFailed: "Connection unavailable. Check the endpoint and token file.", unknownLanguage: "Language must be zh or en.",
		noColorHint: "Tip: type help for commands, language zh|en to switch language.", commandsTitle: "Commands", permission: "permission", usage: "Usage", connectedDevices: "Connected devices", notSupported: "not supported",
		footer: "Enter run · help commands · language zh|en switch language · quit exit", offlineHelp: "Help is available offline; remote management commands require a server connection.",
	}
}

func runUI(o options, input io.Reader, output, errorsOut io.Writer) error {
	reader := bufio.NewReader(input)
	path := defaultUIPreferencesPath()
	prefs, _ := loadUIPreferences(path)
	preferredLanguage := o.language
	if preferredLanguage == "" {
		preferredLanguage = prefs.Language
	}
	lang, err := chooseLanguage(preferredLanguage, reader, output, input)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	// A server-side CLI launched beside its own config is managing a local
	// core, even though the admin API is authenticated with a token. Online
	// core means a different machine; infer that distinction from the local
	// config instead of making operators select the wrong label every session.
	if configPath, ok := discoverLocalConfig(o); ok {
		prefs.Core = "local"
		prefs.ConfigPath = configPath
		if prefs.ServerExecutable == "" {
			prefs.ServerExecutable = findServerExecutable()
		}
	} else if o.endpoint != "" && o.token != "" && tokenFileAvailable(o.token) {
		prefs.Core, prefs.Endpoint, prefs.TokenFile = "online", o.endpoint, o.token
	} else if prefs.Core == "online" {
		o.endpoint, o.token = prefs.Endpoint, prefs.TokenFile
	}
	if prefs.Core == "" {
		choice, readErr := chooseMenuItem(reader, input, output, languageText(lang).firstRun,
			[]string{coreLabel("local", lang), coreLabel("online", lang)}, 0, lang)
		if errors.Is(readErr, io.EOF) || choice < 0 {
			return nil
		}
		switch choice {
		case 0:
			prefs.Core = "local"
		case 1:
			prefs.Core = "online"
			prefs, o, err = selectOnlineCore(prefs, o, reader, output, lang)
		default:
			return errors.New(languageText(lang).invalidInput)
		}
		if err != nil {
			return err
		}
		_ = saveUIPreferences(path, prefs)
	}
	if prefs.Core == "local" {
		if prefs.ServerExecutable == "" || prefs.ConfigPath == "" {
			prefs, err = selectLocalCore(prefs, reader, output, lang)
			if err != nil {
				return err
			}
		}
		o.endpoint, o.token, err = localConnection(prefs.ConfigPath)
		if err != nil {
			fmt.Fprintf(errorsOut, "%s: %v\n", languageText(lang).offline, err)
		}
	} else if prefs.Core == "online" && (o.endpoint == "" || o.token == "") {
		prefs, o, err = selectOnlineCore(prefs, o, reader, output, lang)
		if err != nil {
			return err
		}
	}
	_ = saveUIPreferences(path, prefs)
	if interactiveOutput(output) {
		showStartupAnimation(output, lang)
	}
	return runMainMenu(o, prefs, path, lang, reader, output, errorsOut, input)
}

func tokenFileAvailable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func discoverLocalConfig(o options) (string, bool) {
	if !endpointIsLoopback(o.endpoint) || !tokenFileAvailable(o.token) {
		return "", false
	}
	candidates := make([]string, 0, 6)
	if tokenPath, err := filepath.Abs(o.token); err == nil {
		secretDir := filepath.Dir(tokenPath)
		if strings.EqualFold(filepath.Base(secretDir), "secrets") {
			candidates = append(candidates, filepath.Join(filepath.Dir(secretDir), "config.json"))
		}
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "config.json"))
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "config.json"))
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			if _, err := kernel.LoadConfig(candidate); err == nil {
				return candidate, true
			}
		}
	}
	return "", false
}

func endpointIsLoopback(endpoint string) bool {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func chooseLanguage(preferred string, reader *bufio.Reader, output io.Writer, rawInputs ...io.Reader) (uiLanguage, error) {
	if strings.TrimSpace(preferred) != "" {
		lang, err := normalizeLanguage(preferred)
		if err != nil {
			return "", err
		}
		_ = saveUILanguage(defaultUIPreferencesPath(), lang)
		return lang, nil
	}
	if lang, ok := loadUILanguage(defaultUIPreferencesPath()); ok {
		return lang, nil
	}
	var rawInput io.Reader
	if len(rawInputs) > 0 {
		rawInput = rawInputs[0]
	}
	choice, err := chooseMenuItem(reader, rawInput, output, languageText(langEnglish).languagePrompt,
		[]string{languageText(langEnglish).english, languageText(langEnglish).chinese}, 0, langEnglish)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if choice < 0 || errors.Is(err, io.EOF) {
		return "", io.EOF
	}
	lang := langEnglish
	if choice == 1 {
		lang = langChinese
	}
	_ = saveUILanguage(defaultUIPreferencesPath(), lang)
	return lang, nil
}

func defaultUIPreferencesPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "Aries", "ui.json")
}

func loadUILanguage(path string) (uiLanguage, bool) {
	prefs, ok := loadUIPreferences(path)
	if !ok {
		return "", false
	}
	lang, err := normalizeLanguage(prefs.Language)
	return lang, err == nil
}

func loadUIPreferences(path string) (uiPreferences, bool) {
	if path == "" {
		return uiPreferences{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 4096 {
		return uiPreferences{}, false
	}
	var prefs uiPreferences
	if json.Unmarshal(b, &prefs) != nil {
		return uiPreferences{}, false
	}
	return prefs, true
}

func saveUILanguage(path string, lang uiLanguage) error {
	prefs, _ := loadUIPreferences(path)
	prefs.Language = string(lang)
	return saveUIPreferences(path, prefs)
}

func saveUIPreferences(path string, prefs uiPreferences) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(prefs, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, b, 0600)
}

func printBanner(output io.Writer, endpoint string, text uiText, state string) {
	if endpoint == "" {
		endpoint = "—"
	}
	if state == "" {
		state = text.offline
	}
	fmt.Fprintln(output, "╭──────────────────────────────────────────────────────────────────╮")
	fmt.Fprintf(output, "│  ◈  %-61s│\n", text.title)
	fmt.Fprintf(output, "│     %-61s│\n", text.subtitle)
	fmt.Fprintf(output, "│     %s: %-49s│\n", text.endpoint, endpoint)
	fmt.Fprintf(output, "│     %-61s│\n", state)
	fmt.Fprintln(output, "╰──────────────────────────────────────────────────────────────────╯")
}

func runPromptLoop(o options, lang uiLanguage, reader *bufio.Reader, output, errorsOut io.Writer) error {
	text := languageText(lang)
	for {
		fmt.Fprintf(output, "\n%s> ", text.prompt)
		line, err := readInputLine(reader)
		if errors.Is(err, io.EOF) && line == "" {
			fmt.Fprintln(output)
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		words, parseErr := splitCommandLine(line)
		if parseErr != nil {
			fmt.Fprintln(errorsOut, text.parseError)
			continue
		}
		if len(words) == 0 {
			if errors.Is(err, io.EOF) {
				return nil
			}
			continue
		}
		switch strings.ToLower(words[0]) {
		case "quit", "exit", ":q":
			fmt.Fprintln(output, text.goodbye)
			return nil
		case "clear", ":clear":
			fmt.Fprint(output, "\x1b[2J\x1b[H")
			printBanner(output, o.endpoint, text, connectionLabel(o, lang))
			continue
		case "language", "lang":
			if len(words) != 2 {
				fmt.Fprintf(output, "language <zh|en> / 语言切换 <zh|en>\n")
				continue
			}
			newLang, languageErr := normalizeLanguage(words[1])
			if languageErr != nil {
				fmt.Fprintln(errorsOut, languageText(lang).unknownLanguage)
				continue
			}
			lang = newLang
			text = languageText(lang)
			_ = saveUILanguage(defaultUIPreferencesPath(), lang)
			printBanner(output, o.endpoint, text, connectionLabel(o, lang))
			fmt.Fprintln(output, text.languageChanged)
			continue
		case "help", "?", "帮助":
			printLocalizedHelp(output, lang)
			continue
		case "ui":
			fmt.Fprintln(errorsOut, "ui is already running")
			continue
		}
		if strings.EqualFold(words[0], "commands") {
			if registry, ok := readRegistry(o.cache); ok {
				renderCommandIndex(output, registry, lang)
			} else {
				fmt.Fprintln(output, languageText(lang).noCommands)
			}
			continue
		}
		var result bytes.Buffer
		var commandErrors bytes.Buffer
		args := commandArgs(o, words)
		commandErr := executeCLI(args, reader, &result, &commandErrors)
		if commandErr != nil {
			message := strings.TrimSpace(commandErrors.String())
			if message == "" {
				message = commandErr.Error()
			}
			fmt.Fprintf(errorsOut, "✗ %s: %s\n", text.commandError, message)
			continue
		}
		renderCommandResult(output, result.Bytes(), lang)
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func commandArgs(o options, words []string) []string {
	args := make([]string, 0, 10+len(words))
	if o.endpoint != "" {
		args = append(args, "--endpoint", o.endpoint)
	}
	if o.token != "" {
		args = append(args, "--token-file", o.token)
	}
	if o.cache != "" {
		args = append(args, "--cache", o.cache)
	}
	if o.timeout > 0 {
		args = append(args, "--timeout", o.timeout.String())
	}
	return append(args, words...)
}

func connectionLabel(o options, lang uiLanguage) string {
	if o.endpoint == "" || o.token == "" || probeAdmin(o) != nil {
		return languageText(lang).offline
	}
	return languageText(lang).connected
}

func probeAdmin(o options) error {
	if o.endpoint == "" || o.token == "" {
		return errors.New("endpoint and token file are required")
	}
	_, err := loadRegistry(o, false, io.Discard)
	return err
}

func printLocalizedHelp(output io.Writer, lang uiLanguage) {
	text := languageText(lang)
	fmt.Fprintf(output, "%s\n", text.helpHint)
	items := []struct{ path, en, zh string }{
		{"status", "Show node health and listener status", "查看节点健康与监听状态"},
		{"config show", "Show non-secret configuration", "查看非敏感配置"},
		{"config validate", "Validate effective configuration", "校验配置"},
		{"groups list", "List local groups", "列出本机小组"},
		{"groups inspect <group-id>", "Inspect a group", "查看小组详情"},
		{"members list <group-id>", "List group members", "列出小组成员"},
		{"members revoke <group-id> <device-id>", "Revoke a member", "撤销成员"},
		{"members role <group-id> <device-id> --role <admin|member>", "Change a member role", "修改成员角色"},
		{"invites list <group-id>", "List invitation status", "列出邀请码状态"},
		{"storage status", "Show storage and quota", "查看存储与配额"},
		{"language zh|en", "Switch interface language", "切换界面语言"},
		{"quit", "Exit the terminal", "退出控制台"},
	}
	for _, item := range items {
		description := item.en
		if lang == langChinese {
			description = item.zh
		}
		fmt.Fprintf(output, "  %-51s %s\n", item.path, description)
	}
	fmt.Fprintln(output, text.noColorHint)
}

func splitCommandLine(line string) ([]string, error) {
	var words []string
	var word strings.Builder
	var quote rune
	started := false
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if quote != 0 {
			if r == quote {
				quote = 0
				started = true
				continue
			}
			if r == '\\' && quote == '"' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\\') {
				i++
				r = runes[i]
			}
			word.WriteRune(r)
			started = true
			continue
		}
		switch {
		case r == '"' || r == '\'':
			quote = r
			started = true
		case r == ' ' || r == '\t':
			if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteRune(r)
			started = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unmatched quote")
	}
	if started {
		words = append(words, word.String())
	}
	return words, nil
}

func readInputLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if err != nil && !errors.Is(err, io.EOF) {
		return line, err
	}
	return line, err
}

func firstDeploymentWizard(o options, reader *bufio.Reader, output io.Writer, lang uiLanguage) (options, error) {
	text := languageText(lang)
	fmt.Fprintf(output, "\n%s\n", text.setupTitle)
	root, err := askDefault(reader, output, text.installDir, "./aries-node")
	if err != nil {
		return o, err
	}
	publicAddr, err := askDefault(reader, output, text.publicListen, "127.0.0.1:8787")
	if err != nil {
		return o, err
	}
	fmt.Fprintf(output, "  %s\n", text.publicListenHint)
	adminAddr, err := askDefault(reader, output, text.adminListen, "127.0.0.1:8788")
	if err != nil {
		return o, err
	}
	files, err := createDeploymentFiles(root, publicAddr, adminAddr)
	if err != nil {
		return o, err
	}
	fmt.Fprintln(output, text.setupCreated)
	fmt.Fprintf(output, "  %s: %s\n  %s: %s\n  %s: %s\n", text.configPath, files.configPath, text.tokenPath, files.tokenPath, text.logPath, files.logPath)
	fmt.Fprintf(output, "  Start command: aries-server serve --config %q\n", files.configPath)
	serverPath := findServerExecutable()
	if serverPath == "" {
		fmt.Fprintln(output, text.serverMissing)
		return o, nil
	}
	launch, err := askYesNo(reader, output, text.launchNow, true)
	if err != nil {
		return o, err
	}
	if !launch {
		fmt.Fprintln(output, "Start the command above, then run ariesctl ui with the admin endpoint and token-file path.")
		return o, nil
	}
	pid, startErr := startDetachedServer(serverPath, files.configPath, files.logPath)
	if startErr != nil {
		fmt.Fprintf(output, "%s: %v\n", text.serverStartFailed, startErr)
		return o, nil
	}
	fmt.Fprintf(output, "%s (PID %d)\n", text.serverStarted, pid)
	o.endpoint = files.adminURL
	o.token = files.tokenPath
	if err := waitForAdmin(o, 8*time.Second); err != nil {
		fmt.Fprintf(output, "%s: %s\n", text.serverStartFailed, files.logPath)
		return options{}, nil
	}
	return o, nil
}

type deploymentFiles struct {
	root, configPath, tokenPath, logPath, adminURL string
}

func createDeploymentFiles(root, publicAddr, adminAddr string) (deploymentFiles, error) {
	var result deploymentFiles
	config := kernel.DefaultConfig()
	config.PublicListen = strings.TrimSpace(publicAddr)
	config.AdminListen = strings.TrimSpace(adminAddr)
	config.DataDir = "./data"
	config.AdminTokenFile = "./secrets/admin.token"
	config.AllowInsecureLoopback = true
	if err := config.Validate(); err != nil {
		return result, err
	}
	if !isLoopbackListen(config.AdminListen) {
		return result, errors.New("the first-run admin listener must be loopback; use a TLS reverse proxy for remote administration")
	}
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return result, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return result, fmt.Errorf("create installation directory: %w", err)
	}
	secretsDir := filepath.Join(root, "secrets")
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return result, err
	}
	for _, dir := range []string{filepath.Join(root, "data"), filepath.Join(root, "logs")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return result, err
		}
	}
	configPath := filepath.Join(root, "config.json")
	tokenPath := filepath.Join(secretsDir, "admin.token")
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return result, err
	}
	if err := atomicWriteFile(configPath, b, 0600); err != nil {
		return result, fmt.Errorf("write server config: %w", err)
	}
	if _, err := client.CreateTokenFile(tokenPath); err != nil {
		_ = os.Remove(configPath)
		return result, fmt.Errorf("create protected admin token: %w", err)
	}
	adminURL := "http://" + config.AdminListen
	if host, _, splitErr := net.SplitHostPort(config.AdminListen); splitErr == nil && host == "localhost" {
		adminURL = "http://localhost:" + strings.Split(config.AdminListen, ":")[1]
	}
	result = deploymentFiles{root: root, configPath: configPath, tokenPath: tokenPath, logPath: filepath.Join(root, "logs", "server.log"), adminURL: adminURL}
	return result, nil
}

func isLoopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func askDefault(reader *bufio.Reader, output io.Writer, label, defaultValue string) (string, error) {
	fmt.Fprintf(output, "%s [%s]: ", label, defaultValue)
	line, err := readInputLine(reader)
	if errors.Is(err, io.EOF) && line == "" {
		return "", err
	}
	if line == "" {
		line = defaultValue
	}
	return strings.TrimSpace(line), err
}

func askYesNo(reader *bufio.Reader, output io.Writer, label string, defaultYes bool) (bool, error) {
	choice := "Y/n"
	if !defaultYes {
		choice = "y/N"
	}
	fmt.Fprintf(output, "%s [%s]: ", label, choice)
	line, err := readInputLine(reader)
	if line == "" {
		return defaultYes, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", err
}

func connectWizard(o options, reader *bufio.Reader, output io.Writer, lang uiLanguage) (options, error) {
	text := languageText(lang)
	fmt.Fprintf(output, "\n%s\n", text.existingTitle)
	endpoint, err := askDefault(reader, output, text.endpointPrompt, o.endpoint)
	if err != nil {
		return o, err
	}
	tokenPath, err := askDefault(reader, output, text.tokenPrompt, o.token)
	if err != nil {
		return o, err
	}
	if _, err := client.New(endpoint, tokenPath, o.timeout); err != nil {
		return o, err
	}
	o.endpoint, o.token = endpoint, tokenPath
	if err := probeAdmin(o); err != nil {
		return o, err
	}
	return o, nil
}

func findServerExecutable() string {
	if executable, err := os.Executable(); err == nil {
		name := "aries-server"
		if filepath.Ext(executable) == ".exe" {
			name += ".exe"
		}
		candidate := filepath.Join(filepath.Dir(executable), name)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate
		}
	}
	if path, err := exec.LookPath("aries-server"); err == nil {
		return path
	}
	if path, err := exec.LookPath("aries-server.exe"); err == nil {
		return path
	}
	return ""
}

func waitForAdmin(o options, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		api, err := client.New(o.endpoint, o.token, 700*time.Millisecond)
		if err == nil {
			_, err = api.Get(ctx, "/api/v1/admin/status")
		}
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("server did not become ready")
	}
	return lastErr
}

func renderCommandResult(output io.Writer, raw []byte, lang uiLanguage) {
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		fmt.Fprintln(output, strings.TrimSpace(string(raw)))
		return
	}
	if items, ok := result["items"].([]any); ok {
		registry := client.Registry{APIVersion: valueString(result["api_version"]), Items: make([]client.CommandDefinition, 0, len(items))}
		for _, rawItem := range items {
			b, _ := json.Marshal(rawItem)
			var item client.CommandDefinition
			if json.Unmarshal(b, &item) == nil {
				registry.Items = append(registry.Items, item)
			}
		}
		renderCommandIndex(output, registry, lang)
		return
	}
	status := valueString(result["status"])
	summary := valueString(result["summary"])
	if summary == "" {
		fmt.Fprintln(output, strings.TrimSpace(string(raw)))
		return
	}
	mark := "✓"
	if status != "ok" && status != "accepted" && status != "shutting_down" {
		mark = "•"
	}
	fmt.Fprintf(output, "\n%s %s\n", mark, localizeSummary(summary, lang))
	if data, ok := result["data"].(map[string]any); ok {
		keys := make([]string, 0, len(data))
		for key := range data {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			renderField(output, key, data[key], lang, "  ")
		}
	}
	if warnings, ok := result["warnings"].([]any); ok {
		for _, warning := range warnings {
			fmt.Fprintf(output, "  ! %s\n", warning)
		}
	}
	if requestID := valueString(result["request_id"]); requestID != "" {
		fmt.Fprintf(output, "  %s: %s\n", map[string]string{"en": "Request ID", "zh": "请求编号"}[string(lang)], requestID)
	}
}

func renderField(output io.Writer, key string, value any, lang uiLanguage, indent string) {
	if nested, ok := value.(map[string]any); ok {
		fmt.Fprintf(output, "%s%s\n", indent, localizeKey(key, lang))
		keys := make([]string, 0, len(nested))
		for child := range nested {
			keys = append(keys, child)
		}
		sort.Strings(keys)
		for _, child := range keys {
			renderField(output, child, nested[child], lang, indent+"  ")
		}
		return
	}
	if list, ok := value.([]any); ok {
		fmt.Fprintf(output, "%s%s: %d\n", indent, localizeKey(key, lang), len(list))
		for i, item := range list {
			b, _ := json.Marshal(item)
			fmt.Fprintf(output, "%s  [%d] %s\n", indent, i+1, b)
		}
		return
	}
	if value == nil {
		value = languageText(lang).notSupported
	}
	valueText := fmt.Sprint(value)
	if lang == langChinese {
		switch valueText {
		case "listening":
			valueText = "监听中"
		case "available":
			valueText = "可用"
		case "degraded":
			valueText = "降级"
		case "unavailable":
			valueText = "不可用"
		case "disabled":
			valueText = "已关闭"
		case "not_implemented":
			valueText = "尚未实现"
		case "not_supported":
			valueText = "暂不支持"
		}
	}
	fmt.Fprintf(output, "%s%s: %s\n", indent, localizeKey(key, lang), valueText)
}

func renderCommandIndex(output io.Writer, registry client.Registry, lang uiLanguage) {
	fmt.Fprintf(output, "\n%s (API %s)\n", languageText(lang).commandsTitle, registry.APIVersion)
	for _, command := range registry.Items {
		path := command.Path
		fmt.Fprintf(output, "  %-22s %s\n", path, localizeSummary(command.Summary, lang))
	}
}

func localizeSummary(summary string, lang uiLanguage) string {
	if lang != langChinese {
		return summary
	}
	switch summary {
	case "Node status":
		return "节点状态"
	case "Configuration":
		return "当前配置"
	case "Configuration updated":
		return "配置已更新"
	case "Configuration valid":
		return "配置有效"
	case "Group list":
		return "小组列表"
	case "Group details":
		return "小组详情"
	case "Member list":
		return "成员列表"
	case "Invitation status (codes redacted)":
		return "邀请码状态（已隐藏邀请码）"
	case "Storage status":
		return "存储状态"
	case "Server shutdown requested":
		return "已请求关闭服务"
	default:
		return summary
	}
}

func localizeKey(key string, lang uiLanguage) string {
	if lang != langChinese {
		return strings.Title(strings.ReplaceAll(key, "_", " "))
	}
	if translated, ok := map[string]string{
		"admin_listener": "管理监听器", "address": "地址", "state": "状态", "api_version": "API 版本", "connected_devices": "在线设备数", "connected_devices_state": "在线设备状态", "node_id": "节点 ID", "peer_relay_state": "节点中继状态", "pending_control_events": "待处理控制事件", "public_listener": "公开监听器", "server_code": "服务器号", "started_at": "启动时间", "storage_state": "存储状态", "uptime_seconds": "运行时间（秒）", "generation": "密钥代次", "group_id": "小组 ID", "members": "成员", "role": "角色", "status": "状态", "total_bytes": "已用空间（字节）", "quota_bytes": "配额（字节）", "restart_required": "需要重启", "file_storage_enabled": "文件存储已启用", "peer_relay_enabled": "节点中继已启用",
	}[key]; ok {
		return translated
	}
	return strings.ReplaceAll(key, "_", " ")
}

func valueString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func askDefaultAndSet(reader *bufio.Reader, output io.Writer, label, current string) (string, error) {
	value, err := askDefault(reader, output, label, current)
	if err != nil && value == "" {
		return "", err
	}
	return value, nil
}

func normalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("endpoint must include a scheme and host, for example https://server:8788")
	}
	return endpoint, nil
}
