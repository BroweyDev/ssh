package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
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
	"github.com/pkg/sftp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
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
		Enable        bool     `yaml:"enable"`
		AllowedPorts  []int    `yaml:"allowed_ports"`
		AllowedHosts  []string `yaml:"allowed_hosts"`
		LocalForward  bool     `yaml:"local_forward"`
		RemoteForward bool     `yaml:"remote_forward"`
	} `yaml:"port_forward"`
}

// Global configuration and state
var (
	config           Config
	configPath       = "/ssh_config.yml"
	activeForwards   = make(map[string]net.Listener)
	forwardsMutex    sync.RWMutex
	serverPrivateKey ssh.Signer
)

// SSH message structures for port forwarding
type directTCPIPMsg struct {
	DestAddr   string
	DestPort   uint32
	OrigAddr   string
	OrigPort   uint32
}

type forwardedTCPIPMsg struct {
	BindAddr   string
	BindPort   uint32
	OrigAddr   string
	OrigPort   uint32
}

type tcpipForwardMsg struct {
	BindAddr string
	BindPort uint32
}

type tcpipForwardReplyMsg struct {
	BindPort uint32
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func generateHostKey() (ssh.Signer, error) {
	keyPath := "/ssh_host_key"
	
	// Try to load existing key
	if keyBytes, err := os.ReadFile(keyPath); err == nil {
		if key, err := ssh.ParsePrivateKey(keyBytes); err == nil {
			color.Green("Loaded existing host key")
			return key, nil
		}
	}
	
	// Generate new key
	color.Yellow("Generating new host key...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	
	// Convert to SSH format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	
	// Save key to file
	if err := os.WriteFile(keyPath, privateKeyBytes, 0600); err != nil {
		color.Red("Warning: Could not save host key: %v", err)
	}
	
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	
	color.Green("Generated new host key")
	return signer, nil
}

func createDefaultConfig() error {
	defaultConfig := Config{}
	defaultConfig.SSH.Port = "2222"
	defaultConfig.SSH.User = "root"
	defaultConfig.SSH.Password = "password"
	defaultConfig.SSH.Timeout = 300
	defaultConfig.SFTP.Enable = true
	
	// Default port forwarding configuration
	defaultConfig.PortForward.Enable = true
	defaultConfig.PortForward.AllowedPorts = []int{80, 443, 8080, 3000, 5000, 8000, 9000}
	defaultConfig.PortForward.AllowedHosts = []string{"localhost", "127.0.0.1", "::1"}
	defaultConfig.PortForward.LocalForward = true
	defaultConfig.PortForward.RemoteForward = true

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

// Port forwarding helper functions
func isPortAllowed(port int) bool {
	if len(config.PortForward.AllowedPorts) == 0 {
		return true // If no restrictions, allow all ports
	}
	
	for _, allowedPort := range config.PortForward.AllowedPorts {
		if port == allowedPort {
			return true
		}
	}
	return false
}

func isHostAllowed(host string) bool {
	if len(config.PortForward.AllowedHosts) == 0 {
		return true // If no restrictions, allow all hosts
	}
	
	for _, allowedHost := range config.PortForward.AllowedHosts {
		if host == allowedHost {
			return true
		}
	}
	return false
}

// Handle direct-tcpip channel (Local forwarding: ssh -L)
func handleDirectTCPIP(newChannel ssh.NewChannel) {
	if !config.PortForward.Enable || !config.PortForward.LocalForward {
		newChannel.Reject(ssh.Prohibited, "local forwarding disabled")
		return
	}

	var msg directTCPIPMsg
	if err := ssh.Unmarshal(newChannel.ExtraData(), &msg); err != nil {
		newChannel.Reject(ssh.UnknownChannelType, "failed to parse forward data")
		return
	}

	// Check if destination is allowed
	if !isHostAllowed(msg.DestAddr) || !isPortAllowed(int(msg.DestPort)) {
		color.Red("Local forward rejected: %s:%d not allowed", msg.DestAddr, msg.DestPort)
		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("forwarding to %s:%d not allowed", msg.DestAddr, msg.DestPort))
		return
	}

	// Connect to destination
	destAddr := fmt.Sprintf("%s:%d", msg.DestAddr, msg.DestPort)
	destConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		color.Red("Failed to connect to %s: %v", destAddr, err)
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		destConn.Close()
		return
	}

	color.Green("Local forward: %s:%d -> %s", msg.DestAddr, msg.DestPort, destAddr)

	// Handle requests
	go ssh.DiscardRequests(requests)

	// Relay data
	go func() {
		defer channel.Close()
		defer destConn.Close()
		io.Copy(destConn, channel)
	}()

	go func() {
		defer channel.Close()
		defer destConn.Close()
		io.Copy(channel, destConn)
	}()
}

// Handle tcpip-forward request (Remote forwarding: ssh -R)
func handleTCPIPForward(conn *ssh.ServerConn, req *ssh.Request) {
	if !config.PortForward.Enable || !config.PortForward.RemoteForward {
		req.Reply(false, nil)
		return
	}

	var msg tcpipForwardMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		req.Reply(false, nil)
		return
	}

	// Check if binding is allowed
	if !isHostAllowed(msg.BindAddr) || !isPortAllowed(int(msg.BindPort)) {
		color.Red("Remote forward rejected: %s:%d not allowed", msg.BindAddr, msg.BindPort)
		req.Reply(false, nil)
		return
	}

	// Start listening
	bindAddr := fmt.Sprintf("%s:%d", msg.BindAddr, msg.BindPort)
	if msg.BindAddr == "" {
		bindAddr = fmt.Sprintf(":%d", msg.BindPort)
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		color.Red("Failed to bind remote forward %s: %v", bindAddr, err)
		req.Reply(false, nil)
		return
	}

	// Store the listener for cleanup
	forwardKey := fmt.Sprintf("%s:%d", msg.BindAddr, msg.BindPort)
	forwardsMutex.Lock()
	activeForwards[forwardKey] = listener
	forwardsMutex.Unlock()

	color.Green("Remote forward bound: %s", bindAddr)

	// Reply with the actual bound port
	actualPort := uint32(listener.Addr().(*net.TCPAddr).Port)
	reply := tcpipForwardReplyMsg{BindPort: actualPort}
	req.Reply(true, ssh.Marshal(&reply))

	// Handle incoming connections
	go func() {
		defer listener.Close()
		defer func() {
			forwardsMutex.Lock()
			delete(activeForwards, forwardKey)
			forwardsMutex.Unlock()
		}()

		for {
			localConn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(lc net.Conn) {
				defer lc.Close()

				// Create forwarded-tcpip channel
				remoteAddr := lc.RemoteAddr().(*net.TCPAddr)
				payload := ssh.Marshal(&forwardedTCPIPMsg{
					BindAddr: msg.BindAddr,
					BindPort: msg.BindPort,
					OrigAddr: remoteAddr.IP.String(),
					OrigPort: uint32(remoteAddr.Port),
				})

				channel, reqs, err := conn.OpenChannel("forwarded-tcpip", payload)
				if err != nil {
					color.Red("Failed to open forwarded channel: %v", err)
					return
				}

				go ssh.DiscardRequests(reqs)

				// Relay data
				go func() {
					defer channel.Close()
					defer lc.Close()
					io.Copy(lc, channel)
				}()

				io.Copy(channel, lc)
				channel.Close()
			}(localConn)
		}
	}()
}

// Handle cancel-tcpip-forward request
func handleCancelTCPIPForward(req *ssh.Request) {
	var msg tcpipForwardMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		req.Reply(false, nil)
		return
	}

	forwardKey := fmt.Sprintf("%s:%d", msg.BindAddr, msg.BindPort)
	forwardsMutex.Lock()
	if listener, exists := activeForwards[forwardKey]; exists {
		listener.Close()
		delete(activeForwards, forwardKey)
		color.Yellow("Cancelled remote forward: %s", forwardKey)
		req.Reply(true, nil)
	} else {
		req.Reply(false, nil)
	}
	forwardsMutex.Unlock()
}

func handleSession(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	var shell *exec.Cmd
	var ptyFile *os.File

	// Handle session requests
	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				// Parse PTY request
				shell = exec.Command("sh")
				shell.Env = os.Environ()
				
				var err error
				ptyFile, err = pty.Start(shell)
				if err != nil {
					color.Red("Failed to start PTY: %v", err)
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)

			case "window-change":
				if ptyFile != nil && len(req.Payload) >= 8 {
					w := binary.BigEndian.Uint32(req.Payload[0:4])
					h := binary.BigEndian.Uint32(req.Payload[4:8])
					setWinsize(ptyFile, int(w), int(h))
				}
				req.Reply(true, nil)

			case "shell":
				if shell != nil && ptyFile != nil {
					req.Reply(true, nil)
					
					// Relay data between SSH channel and PTY
					go func() {
						io.Copy(ptyFile, channel)
						ptyFile.Close()
					}()
					
					io.Copy(channel, ptyFile)
					shell.Wait()
					return
				}
				req.Reply(false, nil)

			case "subsystem":
				if len(req.Payload) > 4 {
					subsystem := string(req.Payload[4:])
					if subsystem == "sftp" && config.SFTP.Enable {
						req.Reply(true, nil)
						handleSFTP(channel)
						return
					}
				}
				req.Reply(false, nil)

			default:
				req.Reply(false, nil)
			}
		}
	}()
}

func handleSFTP(channel ssh.Channel) {
	server, err := sftp.NewServer(channel)
	if err != nil {
		color.Red("SFTP server init error: %v", err)
		return
	}
	defer server.Close()

	color.Green("SFTP session started")
	if err := server.Serve(); err != nil && err != io.EOF {
		color.Red("SFTP server error: %v", err)
	}
	color.Green("SFTP session ended")
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

func handleConnection(nConn net.Conn) {
	defer nConn.Close()

	// Create SSH server configuration
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			user := conn.User()
			password := string(pass)
			ip := conn.RemoteAddr().String()

			success := config.SSH.User == user && checkPassword(config.SSH.Password, password)
			logLoginAttempt(ip, user, success, "password")

			if success {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication failed")
		},
	}

	serverConfig.AddHostKey(serverPrivateKey)

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()

	// Handle global requests
	go func() {
		for req := range reqs {
			switch req.Type {
			case "tcpip-forward":
				handleTCPIPForward(sshConn, req)
			case "cancel-tcpip-forward":
				handleCancelTCPIPForward(req)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	// Handle channels
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			go handleSession(newChannel)
		case "direct-tcpip":
			go handleDirectTCPIP(newChannel)
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func main() {
	// Load configuration
	if err := loadConfig(); err != nil {
		color.Red("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	// Set default port if not configured
	if config.SSH.Port == "" {
		config.SSH.Port = "2222"
	}

	// Generate or load host key
	var err error
	serverPrivateKey, err = generateHostKey()
	if err != nil {
		color.Red("Failed to generate host key: %v", err)
		os.Exit(1)
	}

	// Display configuration
	isPasswordHashed := isBcryptHash(config.SSH.Password)
	color.Yellow("SSH Server Configuration:")
	color.Yellow("  - Port: %s", config.SSH.Port)
	color.Yellow("  - User: %s", config.SSH.User)
	if isPasswordHashed {
		color.Yellow("  - Using bcrypt hashed password")
	}
	color.Yellow("  - SFTP enabled: %v", config.SFTP.Enable)
	color.Yellow("  - Port forwarding enabled: %v", config.PortForward.Enable)
	if config.PortForward.Enable {
		color.Yellow("    - Local forward (ssh -L): %v", config.PortForward.LocalForward)
		color.Yellow("    - Remote forward (ssh -R): %v", config.PortForward.RemoteForward)
		color.Yellow("    - Allowed ports: %v", config.PortForward.AllowedPorts)
		color.Yellow("    - Allowed hosts: %v", config.PortForward.AllowedHosts)
	}

	color.Blue("Starting SSH server on port %s...", config.SSH.Port)
	color.Yellow("Usage examples:")
	color.Yellow("  SSH:           ssh %s@localhost -p %s", config.SSH.User, config.SSH.Port)
	color.Yellow("  SFTP:          sftp -P %s %s@localhost", config.SSH.Port, config.SSH.User)
	color.Yellow("  Local forward: ssh -L 8080:google.com:80 %s@localhost -p %s", config.SSH.User, config.SSH.Port)
	color.Yellow("  Remote forward: ssh -R 9000:localhost:22 %s@localhost -p %s", config.SSH.User, config.SSH.Port)
	color.Yellow("  Type 'q' to exit.")

	// Start server
	listener, err := net.Listen("tcp", ":"+config.SSH.Port)
	if err != nil {
		color.Red("Failed to listen on port %s: %v", config.SSH.Port, err)
		os.Exit(1)
	}
	defer listener.Close()

	// Accept connections in goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				color.Red("Failed to accept connection: %v", err)
				continue
			}
			go handleConnection(conn)
		}
	}()

	// Wait for exit command
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "q" {
			color.Yellow("Exit command detected. Closing SSH server...")
			
			// Close all active forwards
			forwardsMutex.Lock()
			for key, listener := range activeForwards {
				listener.Close()
				color.Yellow("Closed forward: %s", key)
			}
			forwardsMutex.Unlock()
			
			os.Exit(0)
		}
	}
}
