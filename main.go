package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	hostPrivateKeySigner ssh.Signer
)

type Std struct {
	Channel ssh.Channel
}

func NewStd(channel ssh.Channel) *Std {
	return &Std{Channel: channel}
}

func (s *Std) Write(p []byte) (n int, err error)  {
	//这里可以自定义保存终端结果，可以保存为 asciinema 格式，方便回放
	//fmt.Printf("%s", string(p))
	return s.Channel.Write(p)
}

func (s *Std) Read(p []byte) (n int, err error) {
	return s.Channel.Read(p)
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
		std := NewStd(channel)
		session.Stdin = std
		session.Stdout = std
		session.Stderr = std

		//_, _ = io.WriteString(std, fmt.Sprintf("connect ssh upstream %s\n\r", host))
		_, _ = std.Write([]byte(fmt.Sprintf("connect ssh upstream %s\n\r", host)))

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
					termEnv := string(req.Payload[4 : termLen+4])
					w, h := parseDims(req.Payload[termLen+4:])
					//_ = session.WindowChange(int(h), int(w))
					_ = session.RequestPty(termEnv, int(h), int(w), modes)
					_ = session.Shell()
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