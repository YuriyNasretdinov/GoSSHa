package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime"
	"time"
)

var (
	user        string
	haveKeyring bool
	keyring     ssh.ClientAuth
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
	clientAuth := []ssh.ClientAuth{}

	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock != "" {
		for {
			sock, err := net.Dial("unix", sshAuthSock)
			if err != nil {
				netErr := err.(net.Error)
				if netErr.Temporary() {
					fmt.Fprintln(os.Stderr, "Got temporary error")
					time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
					continue
				}

				fmt.Fprintln(os.Stderr, "Cannot open connection to SSH agent: "+netErr.Error()+", is temporary: ", netErr.Temporary())
			} else {
				agent := ssh.NewAgentClient(sock)
				clientAuth = append(clientAuth, ssh.ClientAuthAgent(agent))
			}

			break
		}
	}

	if haveKeyring {
		clientAuth = append(clientAuth, keyring)
	}

	return &ssh.ClientConfig{
		User: user,
		Auth: clientAuth,
	}
}

func makeKeyring() (res ssh.ClientAuth, err error) {
	var buf [16384]byte

	keyname := os.Getenv("HOME") + "/.ssh/id_rsa"
	fp, err := os.Open(keyname)
	if err != nil {
		return
	}

	n, err := fp.Read(buf[:])
	if err != nil {
		return
	}

	signer, err := ssh.ParsePrivateKey(buf[0:n])
	if err != nil {
		return
	}

	res = ssh.ClientAuthKeyring(&SignerContainer{[]ssh.Signer{signer}})
	return
}

func execute(cmd string, hostname string) (result string, err error) {

	fmt.Fprint(os.Stderr, "\r\033[2KConnecting to "+hostname+"\r")

	client, err := ssh.Dial("tcp", hostname+":22", makeConfig())
	if err != nil {
		return
	}

	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	fmt.Fprint(os.Stderr, "\r\033[2KConnected to "+hostname+"\r")

	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(cmd)
	if err != nil {
		return
	}

	result = b.String()
	return
}

func mssh(cmd string, hostnames []string) (result map[string]string) {
	result = make(map[string]string)
	resultsChan := make(chan *SshResult, 10)

	for _, hostname := range hostnames {
		go func(host string) {
			result, err := execute(cmd, host)
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
	var err error

	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: mssh <cmd> <server1> [... <serverN>]")
		os.Exit(2)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	user = os.Getenv("LOGNAME")

	keyring, err = makeKeyring()
	if err == nil {
		haveKeyring = true
	} else {
		fmt.Fprintln(os.Stderr, "Cannot read private key: "+err.Error())
	}

	result := mssh(os.Args[1], os.Args[2:])

	fmt.Println("\n")

	for k, v := range result {
		fmt.Print(k + ": " + v)
	}
}
