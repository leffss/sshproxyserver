package sshupstream

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func publicKeyAuthFunc(pemBytes, keyPassword []byte) (ssh.AuthMethod, error) {
	// 通过私钥创建一个 Signer 对象，在根据 Signer 对象获取 AuthMethod 对象
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
	// 创建 ssh 配置
	if sshUser == "" {
		return nil, errors.New("ssh_user can not be empty")
	}
	sshConfig := ssh.Config{
		// 兼容交换机等多种设备
		Ciphers: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"},
	}
	config = &ssh.ClientConfig{
		Config: 		 sshConfig,
		Timeout:         timeout,
		User:            sshUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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
	// 连接 ssh
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