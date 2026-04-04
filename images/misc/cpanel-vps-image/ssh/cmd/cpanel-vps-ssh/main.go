package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	colorReset = "\033[0m"
	colorRed   = "\033[0;31m"
	colorGreen = "\033[0;32m"
	colorCyan  = "\033[0;36m"
	colorWhite = "\033[1;37m"
)

type sshConfigFile struct {
	SSHPort     int    `yaml:"SSH_PORT"`
	SSHUsername string `yaml:"SSH_USERNAME"`
	SSHPassword string `yaml:"SSH_PASSWORD"`
	Timeout     string `yaml:"TIMEOUT"`
	SSHLog      string `yaml:"SSH_LOG"`
}

type appConfig struct {
	File         sshConfigFile
	ConfigPath   string
	HomeDir      string
	RootfsDir    string
	HostKeyPath  string
	Timeout      time.Duration
	ProotBinary  string
	LogFilePath  string
	ListenAddr   string
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load SSH config: %v\n", err)
		os.Exit(1)
	}

	signer, err := loadOrCreateHostKey(cfg.HostKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to prepare SSH host key: %v\n", err)
		os.Exit(1)
	}

	serverConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-CPanelVPS-SSH",
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ok := meta.User() == cfg.File.SSHUsername &&
				subtle.ConstantTimeCompare([]byte(cfg.File.SSHPassword), password) == 1
			logAuthAttempt(cfg, meta.User(), remoteHost(meta.RemoteAddr()), ok)
			if !ok {
				return nil, fmt.Errorf("access denied")
			}
			return &ssh.Permissions{}, nil
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on %s: %v\n", cfg.ListenAddr, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("%s[%s]%s SSH listening on %s (%s)\n", colorCyan, "INFO", colorReset, cfg.ListenAddr, cfg.LogFilePath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			continue
		}
		go handleConn(ctx, cfg, conn, serverConfig)
	}
}

func loadConfig() (*appConfig, error) {
	homeDefault := os.Getenv("HOME")
	if homeDefault == "" {
		homeDefault = "/home/container"
	}

	configPath := flag.String("config", filepath.Join(homeDefault, "ssh-conf.yml"), "Path to ssh-conf.yml")
	homeDir := flag.String("home", homeDefault, "Home directory used by the VPS runtime")
	flag.Parse()

	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return nil, err
	}

	var fileCfg sshConfigFile
	if err := yaml.Unmarshal(raw, &fileCfg); err != nil {
		return nil, err
	}

	fileCfg.SSHUsername = strings.TrimSpace(fileCfg.SSHUsername)
	fileCfg.SSHPassword = strings.TrimSpace(fileCfg.SSHPassword)
	fileCfg.SSHLog = strings.TrimSpace(fileCfg.SSHLog)
	if fileCfg.SSHPort <= 0 {
		fileCfg.SSHPort = 2222
	}
	if fileCfg.SSHUsername == "" {
		fileCfg.SSHUsername = "root"
	}
	if fileCfg.SSHPassword == "" {
		return nil, fmt.Errorf("SSH_PASSWORD is required in %s", *configPath)
	}
	if fileCfg.SSHLog == "" {
		fileCfg.SSHLog = "/logs/latest.txt"
	}
	if !filepath.IsAbs(fileCfg.SSHLog) {
		fileCfg.SSHLog = filepath.Join(*homeDir, fileCfg.SSHLog)
	}

	timeout := 5 * time.Minute
	timeoutText := strings.TrimSpace(fileCfg.Timeout)
	if timeoutText != "" {
		if timeoutText == "0" {
			timeout = 0
		} else {
			parsed, err := time.ParseDuration(timeoutText)
			if err != nil {
				return nil, fmt.Errorf("invalid TIMEOUT value %q: %w", timeoutText, err)
			}
			timeout = parsed
		}
	}

	prootBinary := "proot"
	if resolved, err := exec.LookPath("proot"); err == nil {
		prootBinary = resolved
	}

	cfg := &appConfig{
		File:        fileCfg,
		ConfigPath:  *configPath,
		HomeDir:     *homeDir,
		RootfsDir:   filepath.Join(*homeDir, "rootfs"),
		HostKeyPath: filepath.Join(*homeDir, ".cpanel_vps_ssh_hostkey"),
		Timeout:     timeout,
		ProotBinary: prootBinary,
		LogFilePath: fileCfg.SSHLog,
		ListenAddr:  fmt.Sprintf("0.0.0.0:%d", fileCfg.SSHPort),
	}
	return cfg, nil
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if raw, err := os.ReadFile(path); err == nil {
		return parseHostKey(raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privateKey)
}

func parseHostKey(raw []byte) (ssh.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM host key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privateKey)
}

func handleConn(ctx context.Context, cfg *appConfig, netConn net.Conn, serverConfig *ssh.ServerConfig) {
	defer netConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, serverConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	sessionLog(cfg, sshConn.User(), remoteHost(sshConn.RemoteAddr()), "session accepted", colorGreen)

	for {
		select {
		case <-ctx.Done():
			return
		case newChannel, ok := <-chans:
			if !ok {
				return
			}
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
				continue
			}
			go handleSessionChannel(cfg, sshConn, newChannel)
		}
	}
}

type sessionOptions struct {
	term   string
	width  int
	height int
}

func handleSessionChannel(cfg *appConfig, conn *ssh.ServerConn, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	opts := sessionOptions{term: "xterm-256color", width: 120, height: 36}
	var started bool

	for req := range requests {
		switch req.Type {
		case "pty-req":
			opts.term, opts.width, opts.height = parsePtyRequest(req.Payload)
			_ = req.Reply(true, nil)
		case "window-change":
			// The current runtime is launched fresh per SSH session.
			// Window updates are handled after the shell starts.
			_ = req.Reply(true, nil)
		case "shell":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			started = true
			_ = req.Reply(true, nil)
			runSessionCommand(cfg, conn, channel, opts, "")
			return
		case "exec":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			started = true
			command := parseExecRequest(req.Payload)
			_ = req.Reply(true, nil)
			runSessionCommand(cfg, conn, channel, opts, command)
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func runSessionCommand(cfg *appConfig, conn *ssh.ServerConn, channel ssh.Channel, opts sessionOptions, command string) {
	cmd := buildProotCommand(cfg, opts, command)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: uint16(maxInt(opts.width, 80)),
		Rows: uint16(maxInt(opts.height, 24)),
	})
	if err != nil {
		_, _ = io.WriteString(channel, fmt.Sprintf("failed to start shell: %v\r\n", err))
		sendExitStatus(channel, 1)
		return
	}
	defer ptmx.Close()

	sessionLog(cfg, conn.User(), remoteHost(conn.RemoteAddr()), "shell started", colorCyan)

	done := make(chan struct{})
	var timedOut bool
	if cfg.Timeout > 0 {
		time.AfterFunc(cfg.Timeout, func() {
			timedOut = true
			_ = ptmx.Close()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		})
	}

	go func() {
		_, _ = io.Copy(ptmx, channel)
		_ = ptmx.Close()
	}()

	go func() {
		_, _ = io.Copy(channel, ptmx)
		close(done)
	}()

	<-done
	waitErr := cmd.Wait()
	if timedOut {
		_, _ = io.WriteString(channel, "\r\n[SSH timeout reached, session closed]\r\n")
	}

	exitCode := 0
	if waitErr != nil {
		exitCode = exitCodeFromErr(waitErr)
	}
	sessionLog(cfg, conn.User(), remoteHost(conn.RemoteAddr()), fmt.Sprintf("session closed with status %d", exitCode), colorWhite)
	sendExitStatus(channel, exitCode)
}

func buildProotCommand(cfg *appConfig, opts sessionOptions, command string) *exec.Cmd {
	args := []string{
		"--rootfs=" + cfg.RootfsDir,
		"-0",
		"-w", "/root",
		"-b", "/dev",
		"-b", "/sys",
		"-b", "/proc",
		"-b", "/tmp:/tmp",
		"-b", cfg.HomeDir + ":/home/container",
		"-b", cfg.HomeDir + "/logs:/logs",
		"-b", "/opt/cpanel-vps:/opt/cpanel-vps",
	}

	if command == "" {
		args = append(args, "/bin/bash", "--rcfile", "/root/.cpanel_vps_rc", "-i")
	} else {
		args = append(args, "/bin/bash", "-lc", command)
	}

	cmd := exec.Command(cfg.ProotBinary, args...)
	cmd.Env = append(os.Environ(),
		"HOME=/root",
		"TERM="+nonEmpty(opts.term, "xterm-256color"),
	)
	return cmd
}

func logAuthAttempt(cfg *appConfig, username string, ip string, success bool) {
	status := "FAIL"
	color := colorRed
	if success {
		status = "OK"
		color = colorGreen
	}
	line := fmt.Sprintf("%s : %s | IP TRYING TO CONNECT TO THIS SERVER : %s", username, status, ip)
	fmt.Printf("%s[%s]%s %s\n", color, "AUTH", colorReset, line)
	appendLogLine(cfg.LogFilePath, line)
}

func sessionLog(cfg *appConfig, username string, ip string, message string, color string) {
	line := fmt.Sprintf("%s : %s | IP TRYING TO CONNECT TO THIS SERVER : %s", username, message, ip)
	fmt.Printf("%s[%s]%s %s\n", color, "SSH", colorReset, line)
	appendLogLine(cfg.LogFilePath, line)
}

func appendLogLine(path string, line string) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "[%s] %s\n", time.Now().Format(time.RFC3339), line)
}

func remoteHost(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func parsePtyRequest(payload []byte) (string, int, int) {
	if len(payload) < 8 {
		return "xterm-256color", 120, 36
	}
	termLen := binary.BigEndian.Uint32(payload[:4])
	if len(payload) < int(4+termLen+8) {
		return "xterm-256color", 120, 36
	}
	term := string(payload[4 : 4+termLen])
	width := int(binary.BigEndian.Uint32(payload[4+termLen : 8+termLen]))
	height := int(binary.BigEndian.Uint32(payload[8+termLen : 12+termLen]))
	return term, width, height
}

func parseExecRequest(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	commandLen := binary.BigEndian.Uint32(payload[:4])
	if len(payload) < int(4+commandLen) {
		return ""
	}
	return string(payload[4 : 4+commandLen])
}

func sendExitStatus(channel ssh.Channel, code int) {
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: uint32(code)}))
}

func exitCodeFromErr(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func maxInt(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func nonEmpty(value string, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
