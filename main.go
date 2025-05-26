package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/fatih/color"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config represents the YAML configuration structure
type Config struct {
	SSH struct {
		Port     string `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Timeout  int    `yaml:"timeout"`
	} `yaml:"ssh"`
	SFTP struct {
		Enable bool `yaml:"enable"`
	} `yaml:"sftp"`
	PortForward struct {
		Enable bool `yaml:"enable"`
		MaxConnections int `yaml:"max_connections"`
	} `yaml:"port_forward"`
}

// PortForwardManager manages active port forward connections
type PortForwardManager struct {
	mu          sync.RWMutex
	connections map[string]int
	maxConns    int
}

func NewPortForwardManager(maxConns int) *PortForwardManager {
	if maxConns <= 0 {
		maxConns = 10 // default limit
	}
	return &PortForwardManager{
		connections: make(map[string]int),
		maxConns:    maxConns,
	}
}

func (pfm *PortForwardManager) CanAcceptConnection(remoteAddr string) bool {
	pfm.mu.RLock()
	defer pfm.mu.RUnlock()
	
	total := 0
	for _, count := range pfm.connections {
		total += count
	}
	
	return total < pfm.maxConns
}

func (pfm *PortForwardManager) AddConnection(remoteAddr string) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	pfm.connections[remoteAddr]++
}

func (pfm *PortForwardManager) RemoveConnection(remoteAddr string) {
	pfm.mu.Lock()
	defer pfm.mu.Unlock()
	if pfm.connections[remoteAddr] > 0 {
		pfm.connections[remoteAddr]--
		if pfm.connections[remoteAddr] == 0 {
			delete(pfm.connections, remoteAddr)
		}
	}
}

func (pfm *PortForwardManager) GetStats() (int, int) {
	pfm.mu.RLock()
	defer pfm.mu.RUnlock()
	
	total := 0
	for _, count := range pfm.connections {
		total += count
	}
	
	return total, len(pfm.connections)
}

// Global configuration variable
var (
	config     Config
	configPath = "/ssh_config.yml"
	pfManager  *PortForwardManager
)

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func createDefaultConfig() error {
	defaultConfig := Config{}
	defaultConfig.SSH.Port = "2222"
	defaultConfig.SSH.User = "root"
	defaultConfig.SSH.Password = "password"
	defaultConfig.SSH.Timeout = 300
	defaultConfig.SFTP.Enable = true
	defaultConfig.PortForward.Enable = true
	defaultConfig.PortForward.MaxConnections = 10

	yamlData, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, yamlData, 0644)
}

func loadConfig() error {
	// Check if config file exists, create if not
	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		color.Yellow("Configuration file not found. Creating default config at %s", configPath)
		if err := createDefaultConfig(); err != nil {
			color.Red("Error creating default config: %v", err)
			return err
		}
	} else if err != nil {
		color.Red("Error checking config file: %v", err)
		return err
	}

	// Read the config file
	content, err := os.ReadFile(configPath)
	if err != nil {
		color.Red("Error reading config file: %v", err)
		return err
	}

	// Parse YAML into config struct
	if err := yaml.Unmarshal(content, &config); err != nil {
		color.Red("Error parsing config: %v", err)
		return err
	}

	return nil
}

func sftpHandler(sess ssh.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(sess, serverOptions...)
	if err != nil {
		color.Red("sftp server init error: %s", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		color.Green("sftp client exited session.")
	} else if err != nil {
		color.Red("sftp server completed with error: %s", err)
	}
}

// TCP port forwarding handler
func tcpForwardHandler(srv *ssh.Server, conn *ssh.ServerConn, newChan ssh.NewChannel) {
	if !config.PortForward.Enable {
		newChan.Reject(ssh.Prohibited, "port forwarding disabled")
		return
	}

	// Parse the channel request
	d := struct {
		Addr string
		Port uint32
	}{}
	
	if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(ssh.ConnectionFailed, "error parsing forward data")
		return
	}

	// Check connection limits
	remoteAddr := conn.RemoteAddr().String()
	if !pfManager.CanAcceptConnection(remoteAddr) {
		newChan.Reject(ssh.ResourceShortage, "too many port forward connections")
		logPortForward(remoteAddr, fmt.Sprintf("%s:%d", d.Addr, d.Port), false, "connection limit exceeded")
		return
	}

	// Connect to the target
	target := fmt.Sprintf("%s:%d", d.Addr, d.Port)
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		logPortForward(remoteAddr, target, false, fmt.Sprintf("connection failed: %v", err))
		return
	}

	// Accept the channel
	channel, requests, err := newChan.Accept()
	if err != nil {
		targetConn.Close()
		logPortForward(remoteAddr, target, false, fmt.Sprintf("channel accept failed: %v", err))
		return
	}

	// Track the connection
	pfManager.AddConnection(remoteAddr)
	logPortForward(remoteAddr, target, true, "connection established")

	// Handle any requests on this channel (typically none for direct-tcpip)
	go ssh.DiscardRequests(requests)

	// Start copying data bidirectionally
	go func() {
		defer func() {
			targetConn.Close()
			channel.Close()
			pfManager.RemoveConnection(remoteAddr)
			logPortForward(remoteAddr, target, true, "connection closed")
		}()

		var wg sync.WaitGroup
		wg.Add(2)

		// Copy from SSH channel to target
		go func() {
			defer wg.Done()
			io.Copy(targetConn, channel)
		}()

		// Copy from target to SSH channel
		go func() {
			defer wg.Done()
			io.Copy(channel, targetConn)
		}()

		wg.Wait()
	}()
}

func logPortForward(clientIP, target string, success bool, message string) {
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("%s - Port Forward - IP: %s, Target: %s, Success: %v, Message: %s", 
		timestamp, clientIP, target, success, message)

	if success {
		color.Green(logEntry)
	} else {
		color.Red(logEntry)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		color.Red("Error getting home directory: %v", err)
		return
	}

	logFile := filepath.Join(homeDir, "ssh.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		color.Red("Error opening log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry + "\n"); err != nil {
		color.Red("Error writing to log file: %v", err)
	}
}

func logLoginAttempt(ip, user string, success bool, method string) {
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("%s - IP: %s, User: %s, Method: %s, Success: %v", timestamp, ip, user, method, success)

	if success {
		color.Green(logEntry)
	} else {
		color.Red(logEntry)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		color.Red("Error getting home directory: %v", err)
		return
	}

	logFile := filepath.Join(homeDir, "ssh.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		color.Red("Error opening log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry + "\n"); err != nil {
		color.Red("Error writing to log file: %v", err)
	}
}

func handleSession(s ssh.Session) {
	cmd := exec.Command("sh")
	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			color.Red("Error starting pty: %v", err)
			io.WriteString(s, fmt.Sprintf("Error starting pty: %v\n", err))
			s.Exit(1)
			return
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, s)
		}()
		io.Copy(s, f)
		cmd.Wait()
	} else {
		io.WriteString(s, "No PTY requested.\n")
		s.Exit(1)
	}
}

// Function to detect if a string is a bcrypt hash
func isBcryptHash(str string) bool {
	return len(str) > 0 && (strings.HasPrefix(str, "$2a$") ||
		strings.HasPrefix(str, "$2b$") ||
		strings.HasPrefix(str, "$2y$"))
}

// Function to check password - handles both bcrypt and plaintext
func checkPassword(storedPassword, inputPassword string) bool {
	// If it looks like a bcrypt hash, use bcrypt comparison
	if isBcryptHash(storedPassword) {
		err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
		return err == nil
	}

	// Otherwise, use plain text comparison
	return storedPassword == inputPassword
}

// Function to print port forward statistics
func printPortForwardStats() {
	if pfManager != nil {
		total, clients := pfManager.GetStats()
		if total > 0 {
			color.Cyan("Port Forward Stats: %d active connections from %d clients", total, clients)
		}
	}
}

func main() {
	// Load configuration from YAML file
	if err := loadConfig(); err != nil {
		color.Red("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	// Initialize port forward manager
	pfManager = NewPortForwardManager(config.PortForward.MaxConnections)

	// Set default port if not configured
	if config.SSH.Port == "" {
		config.SSH.Port = "2222"
	}

	// Parse timeout to duration
	var sshTimeout time.Duration
	if config.SSH.Timeout > 0 {
		sshTimeout = time.Duration(config.SSH.Timeout) * time.Second
	}

	// Detect if password is hashed
	isPasswordHashed := isBcryptHash(config.SSH.Password)

	server := &ssh.Server{
		Addr: ":" + config.SSH.Port,
		PasswordHandler: func(ctx ssh.Context, pass string) bool {
			// Make sure username matches and check password
			success := config.SSH.User == ctx.User() && checkPassword(config.SSH.Password, pass)
			logLoginAttempt(ctx.RemoteAddr().String(), ctx.User(), success, "password")
			return success
		},
	}

	// Add SFTP support if enabled
	if config.SFTP.Enable {
		server.SubsystemHandlers = map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler,
		}
	}

	// Add port forwarding support if enabled
	if config.PortForward.Enable {
		server.ChannelHandlers = map[string]ssh.ChannelHandler{
			"direct-tcpip": tcpForwardHandler,
		}
	}

	if config.SSH.Password == "" {
		server.PasswordHandler = nil
	}

	server.Handle(handleSession)

	if sshTimeout > 0 {
		server.MaxTimeout = sshTimeout
		server.IdleTimeout = sshTimeout
		color.Yellow("SSH server configured with timeouts:")
		color.Yellow("  - Maximum connection duration: %s", sshTimeout)
		color.Yellow("  - Idle timeout: %s", sshTimeout)
	}

	color.Yellow("SSH Server Configuration:")
	color.Yellow("  - User: %s", config.SSH.User)
	if isPasswordHashed {
		color.Yellow("  - Using bcrypt hashed password")
	}
	color.Yellow("  - SFTP enabled: %v", config.SFTP.Enable)
	color.Yellow("  - Port Forward enabled: %v", config.PortForward.Enable)
	if config.PortForward.Enable {
		color.Yellow("  - Max port forward connections: %d", config.PortForward.MaxConnections)
	}
	color.Blue("Starting SSH server on port %s...", config.SSH.Port)
	color.Yellow("  - Type 'q' to exit, 's' for stats.")

	// Start the SSH server in a separate goroutine
	go func() {
		log.Fatal(server.ListenAndServe())
	}()

	// Scanner to detect input
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "q":
			color.Yellow("Exit command detected. Closing the SSH server.")
			os.Exit(0)
		case "s":
			printPortForwardStats()
		default:
			color.Yellow("Commands: 'q' to quit, 's' for port forward stats")
		}
	}
}
