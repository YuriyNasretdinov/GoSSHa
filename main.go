package main

import (
	"bufio"
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var (
	user                string
	haveKeyring         bool
	keyring             ssh.ClientAuth
	connectedHosts      map[string]*ssh.ClientConn
	connectedHostsMutex sync.Mutex
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
		err      error
	}

	ScpResult struct {
		hostname string
		err      error
	}

	ProxyRequest struct {
		Action  string
		Cmd     string
		Hosts   []string
		Timeout uint64
	}

	MsshReply struct {
		Hostname string
		Result   string
		Err      error
	}

	MsshFinalReply struct {
		TotalTime     float64
		TimedOutHosts map[string]bool
	}

	ConnectionProgress struct {
		ConnectedHost string
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

func reportErrorToUser(msg string) {
	fmt.Fprintln(os.Stderr, msg)
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
					time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
					continue
				}

				fmt.Fprintln(os.Stderr, "Cannot open connection to SSH agent: "+netErr.Error())
			} else {
				agent := ssh.NewAgentClient(sock)
				identities, err := agent.RequestIdentities()
				if err != nil {
					fmt.Fprintln(os.Stderr, "Cannot request identities from ssh-agent: "+err.Error())
				} else if len(identities) > 0 {
					clientAuth = append(clientAuth, ssh.ClientAuthAgent(agent))
				}
			}

			break
		}
	}

	if keyring != nil {
		clientAuth = append(clientAuth, keyring)
	}

	return &ssh.ClientConfig{
		User: user,
		Auth: clientAuth,
	}
}

func makeSigner(keyname string) (signer ssh.Signer, err error) {
	fp, err := os.Open(keyname)
	if err != nil {
		if !os.IsNotExist(err) {
			reportErrorToUser("Could not parse " + keyname + ": " + err.Error())
		}
		return
	}
	defer fp.Close()

	buf, err := ioutil.ReadAll(fp)
	if err != nil {
		reportErrorToUser("Could not read " + keyname + ": " + err.Error())
		return
	}

	if bytes.Contains(buf, []byte("ENCRYPTED")) {
		var (
			tmpfp *os.File
			out   []byte
		)

		tmpfp, err = ioutil.TempFile("", "key")
		if err != nil {
			reportErrorToUser("Could not create temporary file: " + err.Error())
			return
		}

		tmpName := tmpfp.Name()

		defer func() { tmpfp.Close(); os.Remove(tmpName) }()

		reportErrorToUser(keyname + " is encrypted, using ssh-keygen to decrypt it")

		_, err = tmpfp.Write(buf)

		if err != nil {
			reportErrorToUser("Could not write encrypted key contents to temporary file: " + err.Error())
			return
		}

		err = tmpfp.Close()
		if err != nil {
			reportErrorToUser("Could not close temporary file: " + err.Error())
			return
		}

		cmd := exec.Command("ssh-keygen", "-f", tmpName, "-N", "", "-p")
		out, err = cmd.CombinedOutput()
		if err != nil {
			reportErrorToUser("Could not decrypt key: " + err.Error() + ", command output: " + string(out))
			return
		}

		tmpfp, err = os.Open(tmpName)
		if err != nil {
			reportErrorToUser("Cannot open back " + tmpName)
			return
		}

		buf, err = ioutil.ReadAll(tmpfp)
		if err != nil {
			return
		}

		tmpfp.Close()
		os.Remove(tmpName)
	}

	signer, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		reportErrorToUser("Could not parse " + keyname + ": " + err.Error())
		return
	}

	return
}

func makeKeyring() ssh.ClientAuth {
	signers := []ssh.Signer{}
	keys := []string{os.Getenv("HOME") + "/.ssh/id_rsa", os.Getenv("HOME") + "/.ssh/id_dsa"}

	for _, keyname := range keys {
		signer, err := makeSigner(keyname)
		if err == nil {
			signers = append(signers, signer)
		}
	}

	if len(keys) == 0 {
		return nil
	}

	return ssh.ClientAuthKeyring(&SignerContainer{signers})
}

func getConnection(hostname string) (conn *ssh.ClientConn, err error) {
	connectedHostsMutex.Lock()
	conn = connectedHosts[hostname]
	connectedHostsMutex.Unlock()
	if conn != nil {
		return
	}

	conn, err = ssh.Dial("tcp", hostname+":22", makeConfig())
	if err != nil {
		return
	}

	sendProxyReply(&ConnectionProgress{ConnectedHost: hostname})

	connectedHostsMutex.Lock()
	connectedHosts[hostname] = conn
	connectedHostsMutex.Unlock()

	return
}

func uploadFile(target string, contents []byte, hostname string) (err error) {
	conn, err := getConnection(hostname)
	if err != nil {
		return
	}

	session, err := conn.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	cmd := "cat >" + target
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return
	}

	err = session.Start(cmd)
	if err != nil {
		return
	}

	_, err = stdinPipe.Write(contents)
	if err != nil {
		return
	}

	err = stdinPipe.Close()
	if err != nil {
		return
	}

	err = session.Wait()
	if err != nil {
		return
	}

	return
}

func execute(cmd string, hostname string) (result string, err error) {
	conn, err := getConnection(hostname)
	if err != nil {
		return
	}

	session, err := conn.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(cmd)
	defer session.Close()
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
				reportErrorToUser("Error at " + host + ": " + err.Error())
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

func mscp(source, target string, hostnames []string) (result map[string]error) {
	fp, err := os.Open(source)
	if err != nil {
		panic("Cannot open " + source + ": " + err.Error())
	}

	defer fp.Close()

	contents, err := ioutil.ReadAll(fp)
	if err != nil {
		panic("Cannot read " + source + " contents: " + err.Error())
	}

	result = make(map[string]error)
	resultsChan := make(chan *ScpResult, 10)

	for _, hostname := range hostnames {
		go func(host string) {
			resultsChan <- &ScpResult{hostname: host, err: uploadFile(target, contents, host)}
		}(hostname)
	}

	for i := 0; i < len(hostnames); i++ {
		res := <-resultsChan
		result[res.hostname] = res.err
	}

	return
}

func initialize() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	user = os.Getenv("LOGNAME")

	keyring = makeKeyring()
	connectedHosts = make(map[string]*ssh.ClientConn)
}

func sendProxyReply(response interface{}) {
	buf, err := json.Marshal(response)
	if err != nil {
		panic("Could not marshal json reply: " + err.Error())
	}

	fmt.Println(string(buf))
}

func runMsshAction(msg *ProxyRequest) {
	if msg.Cmd == "" {
		reportErrorToUser("Empty 'cmd'")
		return
	}

	if msg.Timeout == 0 {
		reportErrorToUser("Empty 'Timeout'")
		return
	}

	startTime := time.Now().UnixNano()

	responseChannel := make(chan *SshResult, 10)
	timeoutChannel := time.After(time.Millisecond * time.Duration(msg.Timeout))

	timedOutHosts := make(map[string]bool)

	for _, hostname := range msg.Hosts {
		timedOutHosts[hostname] = true

		go func(host string) {
			res, err := execute(msg.Cmd, host)
			responseChannel <- &SshResult{hostname: host, result: res, err: err}
		}(hostname)
	}

	stop := false

	for i := 0; i < len(msg.Hosts); i++ {
		select {
		case <-timeoutChannel:
			stop = true
			break
		case msg := <-responseChannel:
			delete(timedOutHosts, msg.hostname)
			sendProxyReply(MsshReply{Hostname: msg.hostname, Result: msg.result, Err: msg.err})
		}

		if stop {
			break
		}
	}

	connectedHostsMutex.Lock()
	for hostname, _ := range timedOutHosts {
		delete(connectedHosts, hostname)
	}
	connectedHostsMutex.Unlock()

	sendProxyReply(MsshFinalReply{TotalTime: float64(time.Now().UnixNano()-startTime) / 1e9, TimedOutHosts: timedOutHosts})
}

func runProxy() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		msg := new(ProxyRequest)

		line := scanner.Bytes()
		err := json.Unmarshal(line, msg)
		if err != nil {
			reportErrorToUser("Cannot parse JSON: " + err.Error())
			continue
		}

		switch {
		case msg.Action == "mssh":
			runMsshAction(msg)
		default:
			reportErrorToUser("Unsupported action: " + msg.Action)
		}
	}

	if err := scanner.Err(); err != nil {
		reportErrorToUser("Error reading stdin: " + err.Error())
	}
}

func main() {
	command := filepath.Base(os.Args[0])

	if command == "mscp" {
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: mscp <source> <target> <server1> [... <serverN>]")
			os.Exit(2)
		}

		initialize()
		result := mscp(os.Args[1], os.Args[2], os.Args[3:])

		fmt.Println("\n")

		for k, v := range result {
			fmt.Println(k+": ", v)
		}
	} else if command == "mssh" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: mssh <cmd> <server1> [... <serverN>]")
			os.Exit(2)
		}

		initialize()
		result := mssh(os.Args[1], os.Args[2:])

		fmt.Println("\n")

		for k, v := range result {
			fmt.Print(k + ": " + v)
		}
	} else {
		initialize()

		runProxy()
	}
}
