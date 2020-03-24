package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/ssh"
)

var (
	hostPrivateKeySigner ssh.Signer
)

// asciinema 官方目前只支持 o 和 i，目前 size 还未支持，只有 o 就足够了
const V2Version = 2
const V2OutputEvent = "o"
const V2InputEvent = "i"
const V2SizeEvent = "size"

type CastV2Theme struct {
	Fg string `json:"fg"`
	Bg string `json:"bg"`
	Palette string `json:"palette"`
}

type CastV2Header struct {
	Version uint `json:"version"`
	Width int `json:"width"`
	Height int `json:"height"`
	Timestamp int64 `json:"timestamp,omitempty"`
	Duration float32 `json:"duration,omitempty"`
	Title string  `json:"title,omitempty"`
	Command string  `json:"command,omitempty"`
	Env *map[string]string `json:"env,omitempty"`
	// this is a pointer only because that's the easiest way to force Golang's
	// JSON marshaller to not emit it if empty
	Theme *CastV2Theme `json:"theme,omitempty"`
	IdleTimeLimit float32 `json:"idle_time_limit,omitempty"`
	outputStream *json.Encoder
}

type CastMetadata struct {
	Version   uint
	Width     int
	Height    int
	Title     string
	Timestamp time.Time
	Duration  float32
	Command   string
	Env       map[string]string
	IdleTimeLimit float32
}

func NewCastV2(meta *CastMetadata, fd io.Writer) (*CastV2Header, error) {
	var c CastV2Header
	c.Version = meta.Version
	c.Width = meta.Width
	c.Height = meta.Height
	if meta.Title != "" {
		c.Title = meta.Title
	}

	if meta.Timestamp.Unix() > 0 {
		c.Timestamp = meta.Timestamp.Unix()
	}

	if meta.Duration > 0.0 {
		c.Duration = meta.Duration
	}

	if meta.Command != "" {
		c.Command = meta.Command
	}

	if meta.Env != nil {
		c.Env = &meta.Env
	}

	if meta.IdleTimeLimit > 0.0 {
		c.IdleTimeLimit = meta.IdleTimeLimit
	}

	c.outputStream = json.NewEncoder(fd)
	return &c, nil
}

func (c *CastV2Header) PushHeader() error {
	return c.outputStream.Encode(c)
}

func (c *CastV2Header) PushData(start time.Time, ts time.Time, event string, data []byte) error {
	out := make([]interface{}, 3)
	out[0] = ts.Sub(start).Seconds()
	out[1] = event
	out[2] = string(data)
	// 使用这种方法能避免 \u001b 被写成 \x1b 导致 asciinema 回放错误
	return c.outputStream.Encode(out)
}

type Std struct {
	id string
	channel ssh.Channel
	shell string
	term string
	width int
	height int
	startTime time.Time
	file *os.File
	castV2 *CastV2Header
}

func NewStd(channel ssh.Channel, shell, term string, width, height int) *Std {
	return &Std{
		id: uuid.NewV4().String(),
		channel: channel,
		shell: shell,
		term: term,
		width: width,
		height: height,
		startTime: time.Now(),
	}
}

func (s *Std) Write(p []byte) (n int, err error)  {
	//这里可以自定义保存终端结果，可以保存为 asciinema 格式，方便回放
	now := time.Now()
	s.castV2.PushData(s.startTime, now, V2OutputEvent, p)
	return s.channel.Write(p)
}

func (s *Std) Read(p []byte) (n int, err error) {
	return s.channel.Read(p)
}

func (s *Std) SetTerm(term string) {
	s.term = term
}

func (s *Std) WriteHeader() {
	f, _ := os.Create(s.id)
	s.file = f

	castMetadata := &CastMetadata{
		Version:       V2Version,
		Width:         s.width,
		Height:        s.height,
		//Title:         "",
		Timestamp:     s.startTime,
		//Duration:      0,
		//Command:       "",
		Env:           map[string]string{"SHELL": s.shell, "TERM": s.term},
		//IdleTimeLimit: 0,
	}

	castV2, _ := NewCastV2(castMetadata, s.file)
	castV2.PushHeader()
	s.castV2 = castV2
}

func (s *Std) CloseFile() {
	_ = s.file.Close()
}

func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	log.Println(conn.RemoteAddr(), "auth with", key.Type())
	return nil, nil
}

func passwordAuth(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)  {
	_ = password
	log.Println(conn.RemoteAddr(), "auth with password")
	return nil, nil
}

// parseDims extracts two uint32s from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

func publicKeyAuthFunc(pemBytes, keyPassword []byte) (ssh.AuthMethod, error) {
	// Create the Signer for this private key.
	var (
		signer ssh.Signer
		err error
	)
	if string(keyPassword) == "" {
		signer, err = ssh.ParsePrivateKey(pemBytes)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, keyPassword)
	}

	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}

func NewSshClientConfig(sshUser, sshPassword, sshType, sshKey, sshKeyPassword string, timeout time.Duration) (config *ssh.ClientConfig, err error) {
	if sshUser == "" {
		return nil, errors.New("ssh_user can not be empty")
	}
	sshConfig := ssh.Config{
		Ciphers: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"},
	}
	config = &ssh.ClientConfig{
		Config: 		 sshConfig,
		Timeout:         timeout,
		User:            sshUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //这个可以， 但是不够安全
		//HostKeyCallback: hostKeyCallBackFunc(h.Host),
	}
	switch sshType {
	case "password":
		config.Auth = []ssh.AuthMethod{ssh.Password(sshPassword)}
	case "key":
		key, err := publicKeyAuthFunc([]byte(sshKey), []byte(sshKeyPassword))
		if err != nil {
			return nil, err
		}
		config.Auth = []ssh.AuthMethod{key}
	default:
		return nil, fmt.Errorf("unknow ssh auth type: %s", sshType)
	}
	return
}

func NewSshUpstream(host, username, password string, timeout time.Duration) (*ssh.Client, *ssh.Session, error) {
	clientConfig, err := NewSshClientConfig(username, password, "password", "", "", timeout)
	if err != nil {
		return nil, nil, err
	}

	client, err := ssh.Dial("tcp", host, clientConfig)
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}

	return client, session, nil
}

func handleChannels(host, username, password string, timeout time.Duration, sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	defer func() {
		log.Printf("ssh connection close %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
	}()

	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			_ = sshConn.Close()
			return
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			_ = sshConn.Close()
			return
		}

		client, session, err := NewSshUpstream(host, username, password, timeout)
		if err != nil {
			log.Printf("could not connect ssh upstream server")
			_, _ = channel.Write([]byte("could not connect ssh upstream server"))
			_ = channel.Close()
			_ = sshConn.Close()
			return
		}
		defer func() {
			log.Printf("client.close")
			err = client.Close()
			if err != nil {
				log.Printf("client.close err: %s", err)
			}
		}()

		// channel 实现了 io.Reader 与 io.Writer 接口
		//session.Stdin = channel
		//session.Stdout = channel
		//session.Stderr = channel

		// Std 调用 channel 也实现了 io.Reader 与 io.Writer 接口
		std := NewStd(channel, "/bin/sh", "linux", 250, 40)
		session.Stdin = std
		session.Stdout = std
		session.Stderr = std

		//_, _ = io.WriteString(std, fmt.Sprintf("connect ssh upstream %s\n\r", host))
		//_, _ = std.Write([]byte(fmt.Sprintf("connect ssh upstream %s\n\r", host)))

		modes := ssh.TerminalModes{
			ssh.ECHO: 1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		//_ = session.RequestPty("linux", 80, 40, modes)
		//_ = session.Shell()

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false
				switch req.Type {
				case "pty-req":
					ok = true
					termLen := req.Payload[3]
					termType := string(req.Payload[4 : termLen+4])
					w, h := parseDims(req.Payload[termLen+4:])
					//_ = session.WindowChange(int(h), int(w))
					_ = session.RequestPty(termType, int(h), int(w), modes)
					_ = session.Shell()

					std.SetTerm(termType)
					std.WriteHeader()
					defer std.CloseFile()

				case "window-change":
					w, h := parseDims(req.Payload)
					_ = session.WindowChange(int(h), int(w))
					continue
				case "shell":
					ok = true

				case "exec":
					//ok = false
				case "subsystem":
					//ok = false
				case "x11-req":
					//ok = false
				}

				if !ok {
					log.Printf("unsupport %s request...", req.Type)
				}

				_ = req.Reply(ok, nil)
			}
		}(requests)

		// 解决 ctrl + d 退出后，连接不关闭的情况
		go func() {
			time.Sleep(time.Second * 3)
			if err := session.Wait(); err != nil {
				return
			}
			_ = channel.Close()
		}()
	}
}

func init() {
	keyPath := "./ssh_proxy_rsa.key"
	hostPrivateKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}
	hostPrivateKeySigner, err = ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		panic(err)
	}
}

func main() {
	host := "192.168.223.111:22"
	username := "root"
	password := "123456"
	timeout := 5 * time.Second

	config := &ssh.ServerConfig{
		MaxAuthTries: 3,
		PasswordCallback: passwordAuth,
		PublicKeyCallback: keyAuth,
		ServerVersion: "SSH-2.0-go-ssh-proxy-server",	// 必须以 `SSH-2.0-` 开头
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return fmt.Sprintf("Welcome to go ssh proxy server, your address is %s", strings.Split(conn.RemoteAddr().String(), ":")[0])
		},
	}
	config.AddHostKey(hostPrivateKeySigner)

	port := "2222"
	socket, err := net.Listen("tcp", ":" + port)
	if err != nil {
		panic(err)
	}

	for {
		tcpConn, err := socket.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection (%s)", err)
			continue
		}

		// From a standard TCP connection to an encrypted SSH connection
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("failed to handshake (%s)", err)
			continue
		}

		log.Printf("ssh connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		go ssh.DiscardRequests(reqs)

		// Accept all channels
		go handleChannels(host, username, password, timeout, sshConn, chans)
	}
}