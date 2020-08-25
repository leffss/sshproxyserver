package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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
	// sz fmt.Sprintf("%+q", "rz\r**\x18B00000000000000\r\x8a\x11")
	//ZModemSZStart = []byte{13, 42, 42, 24, 66, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 13, 138, 17}
	ZModemSZStart = []byte{42, 42, 24, 66, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 13, 138, 17}
	// sz 结束 fmt.Sprintf("%+q", "\r**\x18B0800000000022d\r\x8a")
	//ZModemSZEnd = []byte{13, 42, 42, 24, 66, 48, 56, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 50, 100, 13, 138}
	ZModemSZEnd = []byte{42, 42, 24, 66, 48, 56, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 50, 100, 13, 138}
	// sz 结束后可能还会发送两个 OO，但是经过测试发现不一定每次都会发送 fmt.Sprintf("%+q", "OO")
	ZModemSZEndOO = []byte{79, 79}

	// rz fmt.Sprintf("%+q", "**\x18B0100000023be50\r\x8a\x11")
	ZModemRZStart = []byte{42, 42, 24, 66, 48, 49, 48, 48, 48, 48, 48, 48, 50, 51, 98, 101, 53, 48, 13, 138, 17}
	// rz -e fmt.Sprintf("%+q", "**\x18B0100000063f694\r\x8a\x11")
	ZModemRZEStart = []byte{42, 42, 24, 66, 48, 49, 48, 48, 48, 48, 48, 48, 54, 51, 102, 54, 57, 52, 13, 138, 17}
	// rz -S fmt.Sprintf("%+q", "**\x18B0100000223d832\r\x8a\x11")
	ZModemRZSStart = []byte{42, 42, 24, 66, 48, 49, 48, 48, 48, 48, 48, 50, 50, 51, 100, 56, 51, 50, 13, 138, 17}
	// rz -e -S fmt.Sprintf("%+q", "**\x18B010000026390f6\r\x8a\x11")
	ZModemRZESStart = []byte{42, 42, 24, 66, 48, 49, 48, 48, 48, 48, 48, 50, 54, 51, 57, 48, 102, 54, 13, 138, 17}
	// rz 结束 fmt.Sprintf("%+q", "**\x18B0800000000022d\r\x8a")
	ZModemRZEnd = []byte{42, 42, 24, 66, 48, 56, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 50, 100, 13, 138}

	// **\x18B0
	ZModemRZCtrlStart = []byte{42, 42, 24, 66, 48}
	// \r\x8a\x11
	ZModemRZCtrlEnd1 = []byte{13, 138, 17}
	// \r\x8a
	ZModemRZCtrlEnd2 = []byte{13, 138}

	// zmodem 取消 \x18\x18\x18\x18\x18\x08\x08\x08\x08\x08
	ZModemCancel = []byte{24, 24, 24, 24, 24, 8, 8, 8, 8, 8}

	hostPrivateKeySigner ssh.Signer
	terminalModes = ssh.TerminalModes{
		ssh.ECHO: 1,
		ssh.TTY_OP_ISPEED: 8192,
		ssh.TTY_OP_OSPEED: 8192,
		ssh.IEXTEN: 0,
	}
)

func ByteContains(x, y []byte) (n []byte, contain bool)  {
	index := bytes.Index(x, y)
	if index == -1 {
		return
	}
	lastIndex := index + len(y)
	n = append(x[:index], x[lastIndex:]...)
	return n, true
}

type Std struct {
	channel ssh.Channel
	SshStdin io.WriteCloser
	SshStdout, SshStderr io.Reader
	id string
	shell string
	term string
	width int
	height int
	startTime time.Time
	file *os.File
	castV2 *asciinema.CastV2Header
	DisableZModemSZ, DisableZModemRZ bool
	ZModemSZ, ZModemRZ, ZModemSZOO bool
	buffSize int
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
		buffSize: 1024,
	}
}

func (s *Std) DisableSZ() {
	s.DisableZModemSZ = true
}

func (s *Std) EnableSZ() {
	s.DisableZModemSZ = false
}

func (s *Std) DisableRZ() {
	s.DisableZModemRZ = true
}

func (s *Std) EnableRZ() {
	s.DisableZModemRZ = false
}

func (s *Std) ReadChannel() {
	readChannel := func() {
		buff := make([]byte, 8192)
		for {
			n, err := s.channel.Read(buff)
			if err != nil {
				return
			}
			_, err = s.SshStdin.Write(buff[:n])
			if err != nil {
				return
			}
		}
	}
	go readChannel()
}

func (s *Std) ReadSsh() {
	readSsh := func(r io.Reader, w io.WriteCloser) {
		buff := make([]byte, 8192)
		for {
			n, err := r.Read(buff)
			if err != nil {
				return
			}
			// 使用 zModem 传输的文件内容不记录
			if s.ZModemSZOO {
				s.channel.Write(buff[:n])
				s.ZModemSZOO = false
				if n < 2 {
					now := time.Now()
					if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, buff[:n]); err != nil {
						log.Println(err)
					}
				} else if n == 2 {
					if buff[0] != ZModemSZEndOO[0] || buff[1] != ZModemSZEndOO[1] {
						now := time.Now()
						if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, buff[:n]); err != nil {
							log.Println(err)
						}
					}
				} else {
					if buff[0] == ZModemSZEndOO[0] && buff[1] == ZModemSZEndOO[1] {
						now := time.Now()
						if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, buff[2:n]); err != nil {
							log.Println(err)
						}
					} else {
						now := time.Now()
						if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, buff[:n]); err != nil {
							log.Println(err)
						}
					}
				}
			} else {
				if s.ZModemSZ {
					s.channel.Write(buff[:n])
					if n < s.buffSize {
						if x, ok := ByteContains(buff[:n], ZModemSZEnd); ok {
							s.ZModemSZ = false
							s.ZModemSZOO = true
							if len(x) != 0 {
								now := time.Now()
								if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, x); err != nil {
									log.Println(err)
								}
							}
						} else if _, ok := ByteContains(buff[:n], ZModemCancel); ok {
							s.ZModemSZ = false
						}
					} else {
						if _, ok := ByteContains(buff[:n], ZModemCancel); ok {
							s.ZModemSZ = false
						}
					}
				} else if s.ZModemRZ {
					s.channel.Write(buff[:n])
					if x, ok := ByteContains(buff[:n], ZModemRZEnd); ok {
						s.ZModemRZ = false
						if len(x) != 0 {
							now := time.Now()
							if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, x); err != nil {
								log.Println(err)
							}
						}
					} else if _, ok := ByteContains(buff[:n], ZModemCancel); ok {
						s.ZModemRZ = false
					} else {
						// rz 上传过程中服务器端还是会给客户端发送一些信息，比如心跳
						startIndex := bytes.Index(buff[:n], ZModemRZCtrlStart)
						if startIndex != -1 {
							endIndex := bytes.Index(buff[:n], ZModemRZCtrlEnd1)
							if endIndex != -1 {
								ctrl := append(ZModemRZCtrlStart, buff[startIndex + len(ZModemRZCtrlStart):endIndex]...)
								ctrl = append(ctrl, ZModemRZCtrlEnd1...)
								info := append(buff[:startIndex], buff[endIndex + len(ZModemRZCtrlEnd1):n]...)
								if len(info) != 0 {
									now := time.Now()
									if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, info); err != nil {
										log.Println(err)
									}
								}
							} else {
								endIndex = bytes.Index(buff[:n], ZModemRZCtrlEnd2)
								if endIndex != -1 {
									ctrl := append(ZModemRZCtrlStart, buff[startIndex + len(ZModemRZCtrlStart):endIndex]...)
									ctrl = append(ctrl, ZModemRZCtrlEnd2...)
									info := append(buff[:startIndex], buff[endIndex + len(ZModemRZCtrlEnd2):n]...)
									if len(info) != 0 {
										now := time.Now()
										if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, info); err != nil {
											log.Println(err)
										}
									}
								} else {
									now := time.Now()
									if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, buff[:n]); err != nil {
										log.Println(err)
									}
								}
							}
						} else {
							now := time.Now()
							if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, buff[:n]); err != nil {
								log.Println(err)
							}
						}
					}
				} else {
					if x, ok := ByteContains(buff[:n], ZModemSZStart); ok {
						if s.DisableZModemSZ {
							s.channel.Write([]byte("sz is disabled\r\n"))
							w.Write(ZModemCancel)
							//w.Write([]byte("\n"))
						} else {
							s.channel.Write(buff[:n])
							if y, ok := ByteContains(x, ZModemCancel); ok {
								// 下载不存在的文件以及文件夹(zmodem 不支持下载文件夹)时
								now := time.Now()
								if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, y); err != nil {
									log.Println(err)
								}
							} else {
								s.ZModemSZ = true
								if len(x) != 0 {
									now := time.Now()
									if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, x); err != nil {
										log.Println(err)
									}
								}
							}
						}
					} else if x, ok := ByteContains(buff[:n], ZModemRZStart); ok {
						if s.DisableZModemRZ {
							s.channel.Write([]byte("rz is disabled\r\n"))
							w.Write(ZModemCancel)
						} else {
							s.channel.Write(buff[:n])
							s.ZModemRZ = true
							if len(x) != 0 {
								now := time.Now()
								if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, x); err != nil {
									log.Println(err)
								}
							}
						}
					} else if x, ok := ByteContains(buff[:n], ZModemRZEStart); ok {
						if s.DisableZModemRZ {
							s.channel.Write([]byte("rz is disabled\r\n"))
							w.Write(ZModemCancel)
						} else {
							s.channel.Write(buff[:n])
							s.ZModemRZ = true
							if len(x) != 0 {
								now := time.Now()
								if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, x); err != nil {
									log.Println(err)
								}
							}
						}
					} else if x, ok := ByteContains(buff[:n], ZModemRZSStart); ok {
						if s.DisableZModemRZ {
							s.channel.Write([]byte("rz is disabled\r\n"))
							w.Write(ZModemCancel)
						} else {
							s.channel.Write(buff[:n])
							s.ZModemRZ = true
							if len(x) != 0 {
								now := time.Now()
								if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, x); err != nil {
									log.Println(err)
								}
							}
						}
					} else if x, ok := ByteContains(buff[:n], ZModemRZESStart); ok {
						if s.DisableZModemRZ {
							s.channel.Write([]byte("rz is disabled\r\n"))
							w.Write(ZModemCancel)
						} else {
							s.channel.Write(buff[:n])
							s.ZModemRZ = true
							if len(x) != 0 {
								now := time.Now()
								if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, x); err != nil {
									log.Println(err)
								}
							}
						}
					} else {
						s.channel.Write(buff[:n])
						now := time.Now()
						if err := s.castV2.PushData(s.startTime, now, asciinema.V2OutputEvent, buff[:n]); err != nil {
							log.Println(err)
						}
					}
				}
			}
		}
	}
	go readSsh(s.SshStdout, s.SshStdin)
	go readSsh(s.SshStderr, s.SshStdin)
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
		//session.Stdin = std
		//session.Stdout = std
		//session.Stderr = std

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
					_ = session.RequestPty(termType, int(h), int(w), terminalModes)
					stdin, _ := session.StdinPipe()
					stdout, _ := session.StdoutPipe()
					stderr, _ := session.StderrPipe()
					std.SshStdin = stdin
					std.SshStdout = stdout
					std.SshStderr = stderr
					//std.DisableSZ()
					//std.DisableRZ()
					std.ReadChannel()
					std.ReadSsh()
					_ = session.Shell()
					std.SetTerm(termType)
					std.InitAsciinema()
					defer std.CloseFile()
					defer session.Close()
					defer stdin.Close()
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
	host := "192.168.223.101:22"
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

	fmt.Println("start ssh proxy server on port:", port)

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
