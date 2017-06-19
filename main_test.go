package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func must(err error, t *testing.T, msg string) {
	if err == nil {
		return
	}
	t.Fatalf("%s: %s", msg, err)
}

const idRsa = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvly6o/1QuNw2kZ9yz80fytEDBGgHcgByPVTx5jTlBPBO8uXF
TBB+LnRP1AUV4fPeyI9gExq74HmgLDVxFSJ7rq1MA2LhvZL64+eZVXgSR6dsk+Le
nEV91rhSUqF3UE4YrW7zDDrvF32FljVuabAGdIIyc1WiS7qZmLQSpvYkPzX7uw0F
Y9QjOacA63DuwSkSfuBlLblRkSA0LeGHuWr0KbYGJTzRV5ZLvbmMFVteluH2Ff/f
01UJGXq4UJGzPxNHc7WVMf/PLLGT525QxJCKwjxMqJiQjiIMkTF7qau/RGCfLloO
VM9P1diRBjwPKBke3UlYFgl193T+Hg3TYhiXjQIDAQABAoIBAHymd8iePVdvS4Q7
ppCPvvuttY4TGJz70dJ7ZxLZHAYJ3YiMEI9oVVfR7dvloJieeglWaRDZdqDcw5dv
PycZt2eALsAg5bSfJA5MP0mKIF4vMZf8/MvTbT1G4REejeRV3y7h8eDWTm1RUkIz
pqMqEnAEOUjwkB+Khr1JXNVbZAzHCUAHPtqDPKU/u07D1eFIiMUYs+Hm5OERa28H
QFnDpnOjBfhUm+TrHpGgbN9TqzScHNMrLg8YE4N9UUOgBMJeJ9aIq+Go53P/Jzsn
kM8os41Am7YNxR0bv07WNWBfq77+E8p734ffrnybMPqnT2b3qrnoh1KmpyZ6hVN0
ODSRw3kCgYEA5fTklhcWvPZEG05yzQkyFYAwTLwEYGae/z0XMnLYg0DL/bKlBwvX
n/FOVZjcmL1K74U1unEF66By6Bd4y0TaHbXJpWtYbQ4+E8pqCnubuzf0eLsnL365
r1Wc9l2D463WsoGEfXT3cNX3KWDrFPEEV9Npu4uwkO8WIjXslYIGNrcCgYEA0+vh
W4UWsePRa7+rOHCv/9xIULHIX2tMn+XbjZI8xr6ZQGtGn5YXfMAyGNDXzzzk9hTa
IEOZJ39NGmpQ94VhDv0j3azIeQhgIR5AtFe3uHdYavrbMt7kSY4oCEVQJcITULxY
qXEFuyhXAnYUlUpg/lcthkItgN3WzQd2g3B1f9sCgYEAsPd0zri4C/WtViJaIMZZ
38gF45ex+oofBCf8aRuO2fuMwRGxBKotZ24prZ/07CqIt6mZPoDqYHna1Bf0IuI6
xTB4HTBuHYcfaNWWI7kakMqv/hVxQ5DPz0oggExZSmcm2brovi+8mP5gtlxarYQJ
ppkRPn5zBCaqrus2xZwJsiMCgYBTpNdm8wm5Hs1KtPUUqs2ctEpKp1EJ8GTm+6eD
okOgwhvk5DKUzH3qvEVJrCxx3HwWcLaDY4rwnvtEwM/CUn+zldBxL0BVHSwsBi/N
vo2CHoDkgKzB0F3UdmpwkUMIFCjhheWMw1Jaw5pMG2UWY6wS1z/drQMeyPB+LkLl
sB6AXwKBgQC4Ii0akKGKu4g06ACQ8IZ03Rz2N3gcNkULYGe0BCaW86pe4W65vl/+
msmpppcSTGGPwGEranLhJC62PPsYzYNB/3Fd5vvl8ONXajj5yM1zX/IvcE7x72ZG
SAmEta/vUMI5a+meJBN+qWp53hUFrJHVUEroT2MJmAvodSyxcqqDGQ==
-----END RSA PRIVATE KEY-----`

const idRsaPub = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+XLqj/VC43DaRn3LPzR/K0QMEaAdyAHI9VPHmNOUE8E7y5cVMEH4udE/UBRXh897Ij2ATGrvgeaAsNXEVInuurUwDYuG9kvrj55lVeBJHp2yT4t6cRX3WuFJSoXdQThitbvMMOu8XfYWWNW5psAZ0gjJzVaJLupmYtBKm9iQ/Nfu7DQVj1CM5pwDrcO7BKRJ+4GUtuVGRIDQt4Ye5avQptgYlPNFXlku9uYwVW16W4fYV/9/TVQkZerhQkbM/E0dztZUx/88ssZPnblDEkIrCPEyomJCOIgyRMXupq79EYJ8uWg5Uz0/V2JEGPA8oGR7dSVgWCXX3dP4eDdNiGJeN nasretdinov@Yuriys-iMac.local`

func startSSHServer() (addr string) {
	conf := &ssh.ServerConfig{}

	k, err := ssh.ParsePrivateKey([]byte(idRsa))
	if err != nil {
		panic(fmt.Errorf("Could not parse private key: %s", err.Error()))
	}
	pub := k.PublicKey()

	conf.AddHostKey(k)

	// copied (with slight modifications) from ssh package test suite
	certChecker := ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return bytes.Equal(k.Marshal(), pub.Marshal())
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "testuser" && bytes.Equal(key.Marshal(), pub.Marshal()) {
				return nil, nil
			}

			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
		IsRevoked: func(c *ssh.Certificate) bool {
			return c.Serial == 666
		},
	}

	conf.PublicKeyCallback = certChecker.Authenticate

	list, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Errorf("Could not listen: %s", err.Error()))
	}

	go handleConnections(list, conf)
	return list.Addr().String()
}

func handleConnections(list net.Listener, conf *ssh.ServerConfig) {
	for {
		tcpConn, err := list.Accept()
		if err != nil {
			panic(fmt.Errorf("Failed to accept incoming connection: %s", err))
		}

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, conf)
		if err != nil {
			panic(fmt.Errorf("Handshake failed: %s", err))
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		go ssh.DiscardRequests(reqs)
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

type channelRequestSuccessMsg struct {
	PeersId uint32 `sshtype:"99"` // we have no legal way of getting PeersId but go client accepts 0 perfectly fine
}

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	ch, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}
	defer ch.Close()

	go io.Copy(os.Stdout, ch)
	go io.Copy(os.Stderr, ch.Stderr())

	go func() {
		rd := bufio.NewReader(ch)
		for {
			ln, err := rd.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return
				}
				panic(fmt.Errorf("Could not read line: %s", err.Error()))
			}
			log.Printf("Got line from client: %s", ln)
		}
	}()

	for req := range requests {
		if req.Type != "exec" {
			panic(fmt.Errorf("Unsupported request type: %s", req.Type))
		}

		// first 4 bytes is length, ignore it
		cmd := string(req.Payload[4:])

		if cmd != "hostname" {
			panic(fmt.Errorf("Unknown cmd: %s", cmd))
		}

		if !req.WantReply {
			panic(fmt.Errorf("Expected that want reply is always set"))
		}

		req.Reply(true, ssh.Marshal(&channelRequestSuccessMsg{}))
		ch.Write([]byte("Test"))

		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(0))
		ch.SendRequest("exit-status", false, b.Bytes())
		return
	}
}

func TestBasic(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("gossha-test-%d", rand.Int()))
	sshDir := filepath.Join(tmpDir, ".ssh")

	must(os.MkdirAll(sshDir, 0700), t, "Could not create temp dir")
	defer os.RemoveAll(tmpDir)

	must(ioutil.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte(idRsa), 0600), t, "Could not write test private key")
	must(ioutil.WriteFile(filepath.Join(sshDir, "id_rsa.pub"), []byte(idRsaPub), 0600), t, "Could not write test public key")

	os.Setenv("LOGNAME", "testuser")
	os.Setenv("HOME", tmpDir)
	os.Setenv("SSH_AUTH_SOCK", "")

	initialize(true)

	addr := startSSHServer()

	go runProxy()

	hostsLeft := map[string]bool{addr: true}

	req := &ProxyRequest{
		Action: "ssh",
		Cmd:    "hostname",
	}

	for h := range hostsLeft {
		req.Hosts = append(req.Hosts, h)
	}

	requestsChan <- req

	timeoutCh := time.After(time.Second * 10)

	for {
		select {
		case reply := <-repliesChan:
			switch reply := reply.(type) {
			case *FinalReply:
				if len(hostsLeft) > 0 {
					t.Fatalf("Some hosts left: %#v", hostsLeft)
				}
				return
			case *Reply:
				delete(hostsLeft, reply.Hostname)

				if !reply.Success {
					t.Fatalf("Failed executing command for %s: %s", reply.Hostname, reply.ErrMsg)
				}

				if reply.Stdout != "Test" {
					t.Fatalf("Expected 'Test', got '%s' in stdout", reply.Stdout)
				}

				if reply.Stderr != "" {
					t.Fatalf("Expected '', got '%s' in stderr", reply.Stderr)
				}
			}
		case <-timeoutCh:
			t.Fatalf("Timed out, hosts left: %#v", hostsLeft)
		}
	}
}
