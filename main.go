package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/leffss/sshproxyserver/asciinema"
	"github.com/leffss/sshproxyserver/sshupstream"
	uuid "github.com/satori/go.uuid"
)

var (
	// sz 下载文件
	ZModemSzStart = fmt.Sprintf("%+q", "rz\r**\x18B00000000000000\r\x8a\x11")
	ZModemSzEnd = fmt.Sprintf("%+q", "\r**\x18B0800000000022d\r\x8a")
	// 经过测试发现不一定会出现，就是两个大写的字母 o, 建议不过滤
	//ZModemSzEnd2 = fmt.Sprintf("%+q", "OO")

	// rz 上传文件
	ZModemRzStart = fmt.Sprintf("%+q", "rz waiting to receive.**\x18B0100000023be50\r\x8a\x11")
	ZModemRzEnd = fmt.Sprintf("%+q", "**\x18B0800000000022d\r\x8a")

	// zmodem 取消 \x18\x18\x18\x18\x18\x08\x08\x08\x08\x08，使用 %+q 的形式无法正确使用 strings.Index 处理
	ZModemCancel = string([]byte{24, 24, 24, 24, 24, 8, 8, 8, 8, 8})

	hostPrivateKeySigner ssh.Signer
	TerminalModes = ssh.TerminalModes{
		ssh.ECHO: 1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
)

type Std struct {
	channel ssh.Channel
	id string
	shell string
	term string
	width int
	height int
	startTime time.Time
	ZModem bool
	file *os.File
	castV2 *asciinema.CastV2Header
}

func NewStd(channel ssh.Channel, shell, term string, width, height int) *Std {
	return &Std{
		channel: channel,
		id: uuid.NewV4().String(),
		shell: shell,
		term: term,
		width: width,
		height: height,
		startTime: time.Now(),
		ZModem: false,
	}
}

func (s *Std) Write(p []byte) (n int, err error)  {
	res := fmt.Sprintf("%+q", string(p))

	// 使用 zModem 传输的文件内容不记录
	if s.ZModem {
		if res == ZModemSzEnd || res == ZModemRzEnd {
			//log.Println("zModem end")
			s.ZModem = false
			now := time.Now()
			if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, []byte("")); err != nil {
				log.Println(err)
			}
		}
		if index := strings.Index(string(p), ZModemCancel); index != -1 {
			//log.Println("zModem cancel")
			s.ZModem = false
		}
	} else {
		if res == ZModemSzStart || res == ZModemRzStart {
			//log.Println("zModem start")
			s.ZModem = true
		} else {
			// 保存结果为 asciinema v2 格式，方便回放
			now := time.Now()
			if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, p); err != nil {
				log.Println(err)
			}
		}
	}
	return s.channel.Write(p)
}

func (s *Std) Read(p []byte) (n int, err error) {
	return s.channel.Read(p)
}

func (s *Std) SetTerm(term string) {
	s.term = term
}

func (s *Std) InitAsciinema() {
	f, _ := os.Create(s.id)
	s.file = f

	castMetadata := &asciinema.CastMetadata{
		Version:       asciinema.V2Version,
		Width:         s.width,
		Height:        s.height,
		//Title:         "",
		Timestamp:     s.startTime,
		//Duration:      0,
		//Command:       "",
		Env:           map[string]string{"SHELL": s.shell, "TERM": s.term},
		//IdleTimeLimit: 0,
	}

	castV2, _ := asciinema.NewCastV2(castMetadata, s.file)
	if err := castV2.PushHeader(); err != nil {
		log.Println(err)
	}
	s.castV2 = castV2
}

func (s *Std) CloseFile() {
	if err := s.file.Close(); err != nil {
		log.Println(err)
	}
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

func handleChannels(host, username, password string, timeout time.Duration, sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, sessionNum uint8) {
	defer func() {
		log.Printf("ssh connection close %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
	}()

	notAllowCloneSession := false
	numSession := sessionNum

	for newChannel := range chans {

		if notAllowCloneSession {	// 仅允许创建一个 session
			_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("not allow clone session more"))
			continue
		}

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

		client, session, err := sshupstream.NewSshUpstream(host, username, password, timeout)
		if err != nil {
			log.Printf("could not connect ssh upstream server")
			_, _ = channel.Write([]byte("could not connect ssh upstream server"))
			_ = channel.Close()
			_ = sshConn.Close()
			return
		}
		defer func() {
			err = client.Close()
			if err != nil {
				log.Printf("client.close err: %s", err)
			}
		}()

		// 控制 clone session 数量
		if sessionNum != 0 {
			numSession--
			if numSession == 0 {
				notAllowCloneSession = true
			}
		}

		// channel 实现了 io.Reader 与 io.Writer 接口
		//session.Stdin = channel
		//session.Stdout = channel
		//session.Stderr = channel

		// Std 通过继承 channel 也实现了 io.Reader 与 io.Writer 接口
		std := NewStd(channel, "/bin/sh", "linux", 250, 40)
		session.Stdin = std
		session.Stdout = std
		session.Stderr = std

		//_, _ = io.WriteString(std, fmt.Sprintf("connect ssh upstream %s\n\r", host))

		// Sessions have out-of-band requests such as "shell", "pty-req", "env" and so on.
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
					_ = session.RequestPty(termType, int(h), int(w), TerminalModes)
					_ = session.Shell()

					std.SetTerm(termType)
					std.InitAsciinema()
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

	var sessionNum uint8 = 1	//控制一个 ssh 连接上能够打开的 session 数， 0 无限制，不推荐

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
		go handleChannels(host, username, password, timeout, sshConn, chans, sessionNum)
	}
}