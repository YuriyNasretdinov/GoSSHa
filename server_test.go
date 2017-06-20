package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type testSSHServer struct {
	hostname   string
	exitStatus int

	// various fault injections
	acceptSleep time.Duration
	cmdSleep    time.Duration

	addr string
}

func (s *testSSHServer) start() {
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
			if conn.User() == testUserName && bytes.Equal(key.Marshal(), pub.Marshal()) {
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

	s.addr = list.Addr().String()

	if verbose {
		log.Printf("Host %s is listening on %s", s.hostname, s.addr)
	}

	go s.handleConnections(list, conf)
}

func (s *testSSHServer) handleConnections(list net.Listener, conf *ssh.ServerConfig) {
	for {
		if s.acceptSleep > 0 {
			time.Sleep(s.acceptSleep)
		}

		tcpConn, err := list.Accept()
		if err != nil {
			panic(fmt.Errorf("Failed to accept incoming connection: %s", err))
		}

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, conf)
		if err != nil {
			panic(fmt.Errorf("Handshake failed: %s", err))
		}

		if verbose {
			log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		}

		go ssh.DiscardRequests(reqs)
		go s.handleChannels(chans)
	}
}

func (s *testSSHServer) handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go s.handleChannel(newChannel)
	}
}

type channelRequestSuccessMsg struct {
	PeersId uint32 `sshtype:"99"` // we have no legal way of getting PeersId but go client accepts 0 perfectly fine
}

func (s *testSSHServer) handleChannel(newChannel ssh.NewChannel) {
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

		if s.cmdSleep > 0 {
			time.Sleep(s.cmdSleep)
		}

		req.Reply(true, ssh.Marshal(&channelRequestSuccessMsg{}))
		ch.Write([]byte(s.hostname))

		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(s.exitStatus))
		ch.SendRequest("exit-status", false, b.Bytes())
		return
	}
}
