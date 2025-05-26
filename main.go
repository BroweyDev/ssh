package main

import (
	"bufio"
	"encoding/binary"
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
	PortForwarding struct {
		EnableLocal  bool `yaml:"enable_local"`
		EnableRemote bool `yaml:"enable_remote"`
	} `yaml:"port_forwarding"`
}

// Global configuration variable
var (
	config     Config
	configPath = "/ssh_config.yml"
	// activeForwards tracks all active port forwards
	activeForwards = make(map[string]net.Listener)
	forwardMutex   sync.Mutex
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
	defaultConfig.PortForwarding.EnableLocal = true
	defaultConfig.PortForwarding.EnableRemote = true

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

// handleForwardTCPIP handles incoming port forwarding requests
func handleForwardTCPIP(srv *ssh.Server, conn *ssh.ServerConn, req *ssh.Request) (bool, []byte) {
	if !config.PortForwarding.EnableRemote {
		return false, nil
	}

	var payload = req.Payload
	var addr string
	var port uint32

	if len(payload) > 4 {
		addr = string(payload[4:])
	}
	if len(payload) >= 4 {
		port = binary.BigEndian.Uint32(payload[:4])
	}

	listenAddr := fmt.Sprintf("%s:%d", addr, port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		color.Red("Failed to listen on %s: %v", listenAddr, err)
		return false, nil
	}

	// Store the listener for later cleanup
	forwardKey := fmt.Sprintf("%s:%d", addr, port)
	forwardMutex.Lock()
	activeForwards[forwardKey] = listener
	forwardMutex.Unlock()

	color.Green("Started remote forwarding from %s", listenAddr)

	// Start accepting connections in a goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					color.Red("Error accepting connection: %v", err)
				}
				return
			}

			remoteAddr := conn.RemoteAddr().String()
			color.Cyan("New forwarding connection from %s", remoteAddr)

			// Forward the connection to the client
			dialAddr := fmt.Sprintf("127.0.0.1:%d", port)
			remote, err := net.Dial("tcp", dialAddr)
			if err != nil {
				color.Red("Failed to dial %s: %v", dialAddr, err)
				conn.Close()
				continue
			}

			// Copy data between the connections
			go func() {
				defer conn.Close()
				defer remote.Close()
				go io.Copy(conn, remote)
				io.Copy(remote, conn)
			}()
		}
	}()

	// Return the port we're listening on
	resp := make([]byte, 4)
	binary.BigEndian.PutUint32(resp, port)
	return true, resp
}

// handleCancelForwardTCPIP handles cancellation of port forwarding
func handleCancelForwardTCPIP(srv *ssh.Server, conn *ssh.ServerConn, req *ssh.Request) (bool, []byte) {
	var payload = req.Payload
	var addr string
	var port uint32

	if len(payload) > 4 {
		addr = string(payload[4:])
	}
	if len(payload) >= 4 {
		port = binary.BigEndian.Uint32(payload[:4])
	}

	forwardKey := fmt.Sprintf("%s:%d", addr, port)
	forwardMutex.Lock()
	defer forwardMutex.Unlock()

	if listener, ok := activeForwards[forwardKey]; ok {
		listener.Close()
		delete(activeForwards, forwardKey)
		color.Yellow("Stopped forwarding from %s", forwardKey)
		return true, nil
	}

	return false, nil
}

func main() {
	// Load configuration from YAML file
	if err := loadConfig(); err != nil {
		color.Red("Failed to load configuration: %v", err)
		os.Exit(1)
	}

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

	if config.SFTP.Enable {
		server.SubsystemHandlers = map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler,
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

	color.Yellow("  - User: %s", config.SSH.User)
	if isPasswordHashed {
		color.Yellow("  - Using bcrypt hashed password")
	}
	color.Yellow("  - SFTP enabled: %v", config.SFTP.Enable)
	color.Yellow("  - Local port forwarding enabled: %v", config.PortForwarding.EnableLocal)
	color.Yellow("  - Remote port forwarding enabled: %v", config.PortForwarding.EnableRemote)
	color.Blue("Starting SSH server on port %s...", config.SSH.Port)
	color.Yellow("  - Type 'q' to exit.")

	// Configure port forwarding if enabled
	if config.PortForwarding.EnableLocal || config.PortForwarding.EnableRemote {
		server.RequestHandlers = map[string]ssh.RequestHandler{
			"tcpip-forward":        handleForwardTCPIP,
			"cancel-tcpip-forward": handleCancelForwardTCPIP,
		}
	}

	// Start the SSH server in a separate goroutine
	go func() {
		log.Fatal(server.ListenAndServe())
	}()

	// Scanner to detect 'q' input
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "q" {
			color.Yellow("Exit command detected. Closing the SSH server.")
			os.Exit(0)
		}
	}
}
