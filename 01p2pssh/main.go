package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/routing"

	"io"
	"log"
	mrand "math/rand"
	"net"
	"strings"

	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	dual "github.com/libp2p/go-libp2p-kad-dht/dual"
	ma "github.com/multiformats/go-multiaddr"
)

var DefaultBootstrapAddresses = []string{
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
	"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",      // mars.i.ipfs.io
	"/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", // mars.i.ipfs.io
}

type P2pStream interface {
	// Read reads data from the connection.
	// Read can be made to time out and return an error after a fixed
	// time limit; see SetDeadline and SetReadDeadline.
	Read(b []byte) (n int, err error)

	// Write writes data to the connection.
	// Write can be made to time out and return an error after a fixed
	// time limit; see SetDeadline and SetWriteDeadline.
	Write(b []byte) (n int, err error)

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// LibP2P code uses golog to log messages. They log with different
	// string IDs (i.e. "swarm"). We can control the verbosity level for
	// all loggers with:
	golog.SetAllLoggers(golog.LevelInfo) // Change to INFO for extra info

	// Parse options from the command line
	listenF := flag.Int("l", 0, "wait for incoming connections")

	target := flag.String("t", "", "target peer address")

	tcpListenF := flag.Int("L", 0, "listen port")
	forwardF := flag.Int("F", 0, "forward port")

	insecureF := flag.Bool("insecure", false, "use an unencrypted connection")
	seedF := flag.Int64("seed", 0, "set random seed for id generation")
	flag.Parse()

	if *listenF == 0 {
		log.Fatal("Please provide a port to bind on with -l")
	}

	// Make a host that listens on the given multiaddress
	ha, err := makeBasicHost(*listenF, true, *seedF)
	if err != nil {
		log.Fatal(err)
	}

	if *tcpListenF != 0 {
		startServer(ctx, ha, *listenF, *insecureF, *tcpListenF)
		<-ctx.Done()
	} else if *forwardF != 0 {
		runClient(ha, *forwardF, *target)
	}

}

// makeBasicHost creates a LibP2P host with a random peer ID listening on the
// given multiaddress. It will use secio if secio is true.
func makeBasicHost(listenPort int, secio bool, randseed int64) (host.Host, error) {

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()
	// If the seed is zero, use real cryptographic randomness. Otherwise, use a
	// deterministic randomness source to make generated keys stay the same
	// across multiple runs
	var r io.Reader
	if randseed == 0 {
		r = rand.Reader
	} else {
		r = mrand.New(mrand.NewSource(randseed))
	}

	// Generate a key pair for this host. We will use it
	// to obtain a valid host ID.
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{libp2p.NoListenAddrs}
	bootstraps, err := DefaultBootstrapPeers()
	if err != nil {
		log.Fatalln(err)
	}
	opts = append(opts,
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort)),
		libp2p.Identity(priv),
		libp2p.Routing(func(host host.Host) (routing.PeerRouting, error) {
			return dual.New(
				ctx, host,
				dual.DHTOption(
					dht.Concurrency(10),
					dht.Mode(dht.ModeAuto),
				),
				dual.WanDHTOption(dht.BootstrapPeers(bootstraps...)),
			)
		}),
	)

	basicHost, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}

	// Build host multiaddress
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", basicHost.ID().Pretty()))

	// Now we can build a full multiaddress to reach this host
	// by encapsulating both addresses:
	addrs := basicHost.Addrs()
	var addr ma.Multiaddr
	// select the address starting with "ip4"
	for _, i := range addrs {
		if strings.HasPrefix(i.String(), "/ip4") {
			addr = i
			break
		}
	}
	fullAddr := addr.Encapsulate(hostAddr)
	log.Printf("I am %s\n", fullAddr)
	if secio {
		log.Printf("Now run \"./p2p-proxy -l %d -d %s -secio\" on a different terminal\n", listenPort+1, fullAddr)
	} else {
		log.Printf("Now run \"go run main.go -l %d -d %s\" on a different terminal\n", listenPort+1, fullAddr)
	}

	return basicHost, nil
}

func getHostAddress(ha host.Host) string {
	// Build host multiaddress
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", ha.ID().Pretty()))

	// Now we can build a full multiaddress to reach this host
	// by encapsulating both addresses:
	addr := ha.Addrs()[0]
	return addr.Encapsulate(hostAddr).String()
}

func startServer(ctx context.Context, ha host.Host, listenPort int, insecure bool, tcpListenF int) {
	fullAddr := getHostAddress(ha)
	log.Printf("I am %s\n", fullAddr)

	// Set a stream handler on host A. /echo/1.0.0 is
	// a user-defined protocol name.
	ha.SetStreamHandler("/x/ssh/1.0.0", func(s network.Stream) {
		log.Println("listener received new stream")
		go newServerConn(s, tcpListenF)
	})

	log.Println("listening for connections")

	if insecure {
		log.Printf("Now run \"./p2p-proxy -l %d -d %s -insecure\" on a different terminal\n", listenPort+1, fullAddr)
	} else {
		log.Printf("Now run \"./p2p-proxy -l %d -d %s\" on a different terminal\n", listenPort+1, fullAddr)
	}
}

func runClient(ha host.Host, proxyPort int, pid string) {

	log.Println("sender opening stream")
	// make a new stream from host B to host A
	// it should be handled on host A by the handler we set above because
	// we use the same /echo/1.0.0 protocol
	// The following code extracts target's the peer ID from the
	// given multiaddress
	peerid, err := peer.Decode(pid)
	if err != nil {
		log.Println(err)
		return
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", proxyPort))
	if err != nil {
		log.Println(err)
		return
	}
	defer listener.Close()
	println("tcp-proxy started.")
	for {
		conn, err := listener.Accept()
		if err != nil {
			println(err)
		} else {
			go newClientConn(conn, ha, peerid)
		}
	}
}

func newClientConn(conn net.Conn, ha host.Host, peerid peer.ID) {
	println("client connected.")
	target, err := ha.NewStream(context.Background(), peerid, "/x/ssh/1.0.0")
	if err != nil {
		log.Println(err)
		return
	}

	defer conn.Close()

	defer target.Close()
	println("backend connected.")
	closed := make(chan bool, 2)
	go ProxyP2p(conn, target, closed)
	go ProxyP2p(target, conn, closed)
	<-closed
	println("Connection closed.")
}

func newServerConn(conn network.Stream, listenerPort int) {
	println("client connected.")
	defer conn.Reset()
	target, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenerPort))
	if err != nil {
		println(err)
	}
	defer target.Close()
	println("backend connected.")
	closed := make(chan bool, 2)
	go ProxyP2p(target, conn, closed)
	go ProxyP2p(conn, target, closed)
	<-closed
	println("Connection closed.")
}

func ProxyP2p(from P2pStream, to P2pStream, closed chan bool) {
	buffer := make([]byte, 4096)
	for {
		n1, err := from.Read(buffer)
		if err != nil {
			println("proxy2 read error", err)
			closed <- true
			return
		}
		_, err = to.Write(buffer[:n1])
		if err != nil {
			println("proxy2 write error", err)
			closed <- true
			return
		}
	}
}

func DefaultBootstrapPeers() ([]peer.AddrInfo, error) {
	ps, err := ParseBootstrapPeers(DefaultBootstrapAddresses)
	if err != nil {
		return nil, fmt.Errorf(`failed to parse hardcoded bootstrap peers: %s
This is a problem with the ipfs codebase. Please report it to the dev team`, err)
	}
	return ps, nil
}

// ParseBootstrapPeer parses a bootstrap list into a list of AddrInfos.
func ParseBootstrapPeers(addrs []string) ([]peer.AddrInfo, error) {
	maddrs := make([]ma.Multiaddr, len(addrs))
	for i, addr := range addrs {
		var err error
		maddrs[i], err = ma.NewMultiaddr(addr)
		if err != nil {
			return nil, err
		}
	}
	return peer.AddrInfosFromP2pAddrs(maddrs...)
}
