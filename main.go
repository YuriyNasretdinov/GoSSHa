package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"io"
	"os"
	"runtime"
)

type (
	MegaPassword struct {
		pass string
	}

	SignerContainer struct {
		signers []ssh.Signer
	}

	SshResult struct {
		hostname string
		result   string
	}
)

func (t *SignerContainer) Key(i int) (key ssh.PublicKey, err error) {
	if i >= len(t.signers) {
		return
	}

	key = t.signers[i].PublicKey()
	return
}

func (t *SignerContainer) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
	if i >= len(t.signers) {
		return
	}

	sig, err = t.signers[i].Sign(rand, data)
	return
}

func (t *MegaPassword) Password(user string) (password string, err error) {
	fmt.Println("User ", user)
	password = t.pass
	return
}

func makeConfig() *ssh.ClientConfig {
	var buf [4096]byte

	keyname := os.Getenv("HOME") + "/.ssh/id_rsa"
	fp, err := os.Open(keyname)
	if err != nil {
		panic("Cannot open " + keyname + ": " + err.Error())
	}

	n, err := fp.Read(buf[:])
	if err != nil {
		panic("Cannot read private key: " + err.Error())
	}

	signer, err := ssh.ParsePrivateKey(buf[0:n])
	if err != nil {
		panic("Cannot parse private key: " + err.Error())
	}

	return &ssh.ClientConfig{
		User: os.Getenv("LOGNAME"),
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthKeyring(&SignerContainer{[]ssh.Signer{signer}}),
		},
	}
}

func execute(config *ssh.ClientConfig, cmd string, hostname string) (result string, err error) {

	fmt.Print("\rConnecting to " + hostname + "\r")

	client, err := ssh.Dial("tcp", hostname+":22", config)
	if err != nil {
		return
	}

	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	fmt.Print("\rConnected to " + hostname + "\r")

	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(cmd)
	if err != nil {
		return
	}

	result = b.String()
	return
}

func mssh(config *ssh.ClientConfig, cmd string, hostnames []string) (result map[string]string) {
	result = make(map[string]string)
	resultsChan := make(chan *SshResult, 10)

	for _, hostname := range hostnames {
		go func(host string) {
			result, err := execute(config, cmd, host)
			if err != nil {
				fmt.Println("Error at " + host + ": " + err.Error())
				result = "(error)\n"
			}

			resultsChan <- &SshResult{hostname: host, result: result}
		}(hostname)
	}

	for i := 0; i < len(hostnames); i++ {
		res := <-resultsChan
		result[res.hostname] = res.result
	}

	return
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: mssh <cmd> <server1> [... <serverN>]")
		os.Exit(2)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	config := makeConfig()
	result := mssh(config, os.Args[1], os.Args[2:])

	fmt.Println("\n")

	for k, v := range result {
		fmt.Print(k + ": " + v)
	}
}
