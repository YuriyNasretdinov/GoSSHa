package main

import (
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func must(err error, msg string) {
	if err == nil {
		return
	}
	panic(fmt.Errorf("%s: %s", msg, err))
}

const verbose = false

const testUserName = "testuser"

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

func launchGoSSHa() {
	initialize(true)
	go runProxy()
}

func TestMain(m *testing.M) {
	code := func() int {
		rand.Seed(time.Now().UnixNano())
		tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("gossha-test-%d", rand.Int()))
		sshDir := filepath.Join(tmpDir, ".ssh")
		must(os.MkdirAll(sshDir, 0700), "Could not create temp dir")
		must(ioutil.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte(idRsa), 0600), "Could not write test private key")
		must(ioutil.WriteFile(filepath.Join(sshDir, "id_rsa.pub"), []byte(idRsaPub), 0600), "Could not write test public key")
		defer os.RemoveAll(tmpDir)

		os.Setenv("LOGNAME", testUserName)
		os.Setenv("HOME", tmpDir)
		os.Setenv("SSH_AUTH_SOCK", "")

		disconnectAfterUse = false
		maxConnections = 0

		launchGoSSHa()

		return m.Run()
	}()

	os.Exit(code)
}

type testResult struct {
	hosts       map[string]*testSSHServer
	slowServers []*testSSHServer
	hostsLeft   map[string]struct{}
	replies     map[string]*Reply
}

func injectFaults(srv *testSSHServer, i int) {
	if i%30 == 0 {
		srv.cmdSleep = maxTimeout * 2
	}

	if i%33 == 0 {
		srv.acceptSleep = maxTimeout
	}

	if i%50 == 0 {
		srv.exitStatus = 1
	}
}

func makeTestResult() *testResult {
	return &testResult{
		hostsLeft: make(map[string]struct{}),
		hosts:     make(map[string]*testSSHServer),
		replies:   make(map[string]*Reply),
	}
}

func waitReply(t *testing.T, r *testResult, timeout time.Duration) {
	timeoutCh := time.After(timeout)

	for {
		select {
		case reply := <-repliesChan:
			switch reply := reply.(type) {
			case *FinalReply:
				return
			case *Reply:
				_, ok := r.hostsLeft[reply.Hostname]
				if !ok {
					t.Fatalf("Got reply for unknown host: %s", reply.Hostname)
				}
				delete(r.hostsLeft, reply.Hostname)

				r.replies[reply.Hostname] = reply
			}
		case <-timeoutCh:
			t.Fatalf("Timed out, hosts left: %#v", r.hostsLeft)
		}
	}

	panic("unreachable")
}

func makeProxyRequest(timeout time.Duration) *ProxyRequest {
	return &ProxyRequest{
		Action:  "ssh",
		Cmd:     "hostname",
		Timeout: uint64(timeout / time.Millisecond),
	}
}

func checkSuccess(t *testing.T, r *testResult) {
	for _, reply := range r.replies {
		srv := r.hosts[reply.Hostname]

		if srv.exitStatus == 0 {
			if !reply.Success {
				t.Fatalf("Failed executing command for %s: %s", reply.Hostname, reply.ErrMsg)
			}
		} else {
			if reply.Success {
				t.Fatalf("Should have failed executing command for %s: %s", reply.Hostname, reply.ErrMsg)
			}
		}

		if reply.Stdout != srv.hostname {
			t.Fatalf("Expected 'Test', got '%s' in stdout", reply.Stdout)
		}

		if reply.Stderr != "" {
			t.Fatalf("Expected '', got '%s' in stderr", reply.Stderr)
		}
	}

	if len(r.hostsLeft) != len(r.slowServers) {
		t.Fatalf("Unexpected number of servers left: %d", len(r.hostsLeft))
	}

	for _, h := range r.slowServers {
		delete(r.hostsLeft, h.addr)
	}

	if len(r.hostsLeft) != 0 {
		t.Fatalf("Extra servers left: %#v", r.hostsLeft)
	}
}

func TestBasic(t *testing.T) {
	r := makeTestResult()

	for i := 0; i < 100; i++ {
		srv := &testSSHServer{
			hostname: fmt.Sprintf("test-%d", i),
		}

		injectFaults(srv, i)

		if srv.cmdSleep > 0 || srv.acceptSleep > 0 {
			r.slowServers = append(r.slowServers, srv)
		}

		srv.start()

		r.hosts[srv.addr] = srv
		r.hostsLeft[srv.addr] = struct{}{}
	}

	req := makeProxyRequest(maxTimeout / 2)

	for h := range r.hostsLeft {
		req.Hosts = append(req.Hosts, h)
	}

	requestsChan <- req

	waitReply(t, r, maxTimeout)
	checkSuccess(t, r)
}

func TestDisconnectAfterUse(t *testing.T) {
	disconnectAfterUse = true
	TestBasic(t)
}

func TestLimitConcurrency(t *testing.T) {
	const (
		maxServers           = 100
		maxConcurrentServers = 10

		tolerance = 0.1

		minAnsweredServers = 50

		softTimeout = maxTimeout
		hardTimeout = softTimeout * 2

		maxConcurrentServersRatio = float64(maxConcurrentServers) / float64(maxServers)
		minAnsweredServersRatio   = float64(minAnsweredServers) / float64(maxServers)

		cmdSleep = time.Duration(
			float64(softTimeout) * (1 - tolerance) * maxConcurrentServersRatio / minAnsweredServersRatio,
		)
	)

	maxConnections = maxConcurrentServers
	maxAnsweredServers := int(math.Ceil(minAnsweredServers/(1-tolerance))) + 1

	r := makeTestResult()

	for i := 0; i < 100; i++ {
		srv := &testSSHServer{
			hostname: fmt.Sprintf("test-concurrency-%d", i),
		}

		srv.cmdSleep = cmdSleep
		srv.start()

		r.hosts[srv.addr] = srv
		r.hostsLeft[srv.addr] = struct{}{}
	}

	req := makeProxyRequest(softTimeout)

	for h := range r.hostsLeft {
		req.Hosts = append(req.Hosts, h)
	}

	requestsChan <- req

	waitReply(t, r, hardTimeout)

	answeredServers := len(r.hosts) - len(r.hostsLeft)

	if answeredServers < minAnsweredServers {
		t.Fatalf("Too few servers responded: got %d, expected %d", answeredServers, minAnsweredServers)
	}

	if answeredServers > maxAnsweredServers {
		t.Fatalf("Too many servers responded: got %d, expected %d", answeredServers, maxAnsweredServers)
	}
}
