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
		Enable         bool     `yaml:"enable"`
		AllowedPorts   []int    `yaml:"allowed_ports"`
		AllowedHosts   []string `yaml:"allowed_hosts"`
		LocalForward   bool     `yaml:"local_forward"`
		RemoteForward  bool     `yaml:"remote_forward"`
		DynamicForward bool     `yaml:"dynamic_forward"`
	} `yaml:"port_forward"`
}

// Global configuration variable
var (
	config     Config
	configPath = "/ssh_config.yml"
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
	
	// Default port forwarding configuration
	defaultConfig.PortForward.Enable = true
	defaultConfig.PortForward.AllowedPorts = []int{80, 443, 8080, 3000, 5000, 8000, 9000}
	defaultConfig.PortForward.AllowedHosts = []string{"localhost", "127.0.0.1", "::1"}
	defaultConfig.PortForward.LocalForward = true
	defaultConfig.PortForward.RemoteForward = true
	defaultConfig.PortForward.DynamicForward = false

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

// Local port forwarding handler (ssh -L)
func handleLocalForward(newCh ssh.NewChannel) {
	if !config.PortForward.Enable || !config.PortForward.LocalForward {
		newCh.Reject(ssh.Prohibited, "local forwarding disabled")
		return
	}

	// Parse the forwarding request
	var payload struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}
	
	if err := ssh.Unmarshal(newCh.ExtraData(), &payload); err != nil {
		newCh.Reject(ssh.UnknownChannelType, "failed to parse forward data")
		return
	}

	// Check if destination is allowed
	if !isHostAllowed(payload.DestAddr) || !isPortAllowed(int(payload.DestPort)) {
		color.Red("Port forwarding rejected: %s:%d not allowed", payload.DestAddr, payload.DestPort)
		newCh.Reject(ssh.Prohibited, fmt.Sprintf("forwarding to %s:%d not allowed", payload.DestAddr, payload.DestPort))
		return
	}

	// Establish connection to destination
	destConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", payload.DestAddr, payload.DestPort))
	if err != nil {
		color.Red("Failed to connect to %s:%d - %v", payload.DestAddr, payload.DestPort, err)
		newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	// Accept the channel
	channel, requests, err := newCh.Accept()
	if err != nil {
		destConn.Close()
		return
	}

	color.Green("Local forward established: %s:%d -> %s:%d", payload.OrigAddr, payload.OrigPort, payload.DestAddr, payload.DestPort)

	// Handle incoming requests
	go ssh.DiscardRequests(requests)

	// Relay data between SSH channel and destination
	go func() {
		defer channel.Close()
		defer destConn.Close()
		io.Copy(channel, destConn)
	}()
	
	go func() {
		defer channel.Close() 
		defer destConn.Close()
		io.Copy(destConn, channel)
	}()
}

// Remote port forwarding handler (ssh -R)
func handleRemoteForward(ctx ssh.Context, bindAddr string, bindPort uint32) bool {
	if !config.PortForward.Enable || !config.PortForward.RemoteForward {
		color.Red("Remote forwarding request rejected: disabled")
		return false
	}

	// Check if binding is allowed
	if !isHostAllowed(bindAddr) || !isPortAllowed(int(bindPort)) {
		color.Red("Remote forwarding rejected: %s:%d not allowed", bindAddr, bindPort)
		return false
	}

	// Start listening on the requested port
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindAddr, bindPort))
	if err != nil {
		color.Red("Failed to bind remote forward %s:%d - %v", bindAddr, bindPort, err)
		return false
	}

	color.Green("Remote forward bound: %s:%d", bindAddr, bindPort)

	// Handle incoming connections
	go func() {
		defer listener.Close()
		
		for {
			conn, err := listener.Accept()
			if err != nil {
				color.Red("Remote forward accept error: %v", err)
				return
			}

			// Handle each connection in a goroutine
			go func(localConn net.Conn) {
				defer localConn.Close()

				// Create a new channel for this connection
				channel, reqs, err := ctx.OpenChannel("forwarded-tcpip", ssh.Marshal(struct {
					DestAddr   string
					DestPort   uint32
					OrigAddr   string
					OrigPort   uint32
				}{
					bindAddr,
					bindPort,
					localConn.RemoteAddr().(*net.TCPAddr).IP.String(),
					uint32(localConn.RemoteAddr().(*net.TCPAddr).Port),
				}))

				if err != nil {
					color.Red("Failed to open forwarded channel: %v", err)
					return
				}

				go ssh.DiscardRequests(reqs)

				// Relay data
				go func() {
					defer channel.Close()
					defer localConn.Close()
					io.Copy(localConn, channel)
				}()

				io.Copy(channel, localConn)
				channel.Close()
			}(conn)
		}
	}()

	return true
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

	// Configure SFTP if enabled
	if config.SFTP.Enable {
		server.SubsystemHandlers = map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler,
		}
	}

	// Configure port forwarding if enabled
	if config.PortForward.Enable {
		// Local forwarding (ssh -L)
		if config.PortForward.LocalForward {
			server.ChannelHandlers = map[string]ssh.ChannelHandler{
				"direct-tcpip": handleLocalForward,
			}
		}

		// Remote forwarding (ssh -R)
		if config.PortForward.RemoteForward {
			server.ReversePortForwardingCallback = handleRemoteForward
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
	color.Yellow("  - Port forwarding enabled: %v", config.PortForward.Enable)
	if config.PortForward.Enable {
		color.Yellow("    - Local forward (ssh -L): %v", config.PortForward.LocalForward)
		color.Yellow("    - Remote forward (ssh -R): %v", config.PortForward.RemoteForward)
		color.Yellow("    - Allowed ports: %v", config.PortForward.AllowedPorts)
		color.Yellow("    - Allowed hosts: %v", config.PortForward.AllowedHosts)
	}
	
	color.Blue("Starting SSH server on port %s...", config.SSH.Port)
	color.Yellow("  - Type 'q' to exit.")

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
