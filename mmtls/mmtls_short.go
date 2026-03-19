package mmtls

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

type MMTLSClientShort struct {
	conn net.Conn

	status int32

	publicEcdh *ecdsa.PrivateKey
	verifyEcdh *ecdsa.PrivateKey
	serverEcdh *ecdsa.PublicKey

	packetReader io.Reader

	handshakeHasher hash.Hash

	serverSeqNum uint32
	clientSeqNum uint32

	Session *Session
}

func NewMMTLSClientShort() *MMTLSClientShort {
	c := &MMTLSClientShort{}

	c.handshakeHasher = sha256.New()

	return c
}

// Handshake performs a 1-RTT ECDHE handshake over a single HTTP request-response.
// This allows the short-link client to establish its own independent session
// without depending on a long-link client.
func (c *MMTLSClientShort) Handshake(host string) error {
	if c.handshakeComplete() {
		return nil
	}

	c.reset()

	pub, verify, err := generateKeyPairs()
	if err != nil {
		return err
	}
	c.publicEcdh = pub
	c.verifyEcdh = verify

	ch := newECDHEHello(&c.publicEcdh.PublicKey, &c.verifyEcdh.PublicKey)
	helloPart := ch.serialize()

	c.handshakeHasher.Write(helloPart)

	// Pack ClientHello into HTTP POST
	helloRecord := createHandshakeRecord(helloPart)
	tlsPayload := helloRecord.serialize()
	c.clientSeqNum++

	header, err := c.buildRequestHeader(host, len(tlsPayload))
	if err != nil {
		return err
	}
	httpPacket := append(header, tlsPayload...)

	// Send
	conn, err := net.Dial("tcp", net.JoinHostPort(host, "80"))
	if err != nil {
		return err
	}

	if _, err := conn.Write(httpPacket); err != nil {
		conn.Close()
		return err
	}

	response, err := c.parseResponse(conn)
	conn.Close()
	if err != nil {
		return err
	}
	log.Debugf("Handshake response(%d):\n%s\n", len(response), hex.Dump(response))

	c.packetReader = bytes.NewReader(response)

	// ServerHello (plaintext)
	serverHelloRecord, err := readRecord(c.packetReader)
	if err != nil {
		return fmt.Errorf("read ServerHello: %w", err)
	}
	c.handshakeHasher.Write(serverHelloRecord.data)
	c.serverSeqNum++

	sh, err := readServerHello(serverHelloRecord.data)
	if err != nil {
		return fmt.Errorf("parse ServerHello: %w", err)
	}
	c.serverEcdh = sh.publicKey

	// DH compute key
	comKey := computeEphemeralSecret(
		c.serverEcdh.X,
		c.serverEcdh.Y,
		c.publicEcdh.D)

	// Handshake traffic key (56 bytes: client key+nonce, server key+nonce)
	trafficKey, err := computeTrafficKeyN(
		comKey,
		buildHkdfInfo("handshake key expansion", c.handshakeHasher),
		56)
	if err != nil {
		return fmt.Errorf("compute traffic key: %w", err)
	}

	// Signature record (encrypted)
	sigRecord, err := readRecord(c.packetReader)
	if err != nil {
		return fmt.Errorf("read Signature: %w", err)
	}
	if err := sigRecord.decrypt(trafficKey, c.serverSeqNum); err != nil {
		return fmt.Errorf("decrypt Signature: %w", err)
	}
	sig, err := readSignature(sigRecord.data)
	if err != nil {
		return fmt.Errorf("parse Signature: %w", err)
	}
	if !verifyEcdsaSignature(c.handshakeHasher, sig.EcdsaSignature) {
		return errors.New("verify ECDSA signature failed")
	}
	c.handshakeHasher.Write(sigRecord.data)
	c.serverSeqNum++

	// NewSessionTicket (encrypted)
	ticketRecord, err := readRecord(c.packetReader)
	if err != nil {
		return fmt.Errorf("read SessionTicket: %w", err)
	}
	if err := ticketRecord.decrypt(trafficKey, c.serverSeqNum); err != nil {
		return fmt.Errorf("decrypt SessionTicket: %w", err)
	}
	tickets, err := readNewSessionTicket(ticketRecord.data)
	if err != nil {
		return fmt.Errorf("parse SessionTicket: %w", err)
	}

	pskAccess := make([]byte, 32)
	hkdf.Expand(
		sha256.New,
		comKey,
		buildHkdfInfo("PSK_ACCESS", c.handshakeHasher)).Read(pskAccess)
	log.Debugf("Short PSK_ACCESS:\n%s\n", hex.Dump(pskAccess))

	pskRefresh := make([]byte, 32)
	hkdf.Expand(
		sha256.New,
		comKey,
		buildHkdfInfo("PSK_REFRESH", c.handshakeHasher)).Read(pskRefresh)
	log.Debugf("Short PSK_REFRESH:\n%s\n", hex.Dump(pskRefresh))

	c.Session = &Session{
		tk:         tickets,
		pskAccess:  pskAccess,
		pskRefresh: pskRefresh,
	}

	c.handshakeHasher.Write(ticketRecord.data)
	c.serverSeqNum++

	// ServerFinish (encrypted)
	sfRecord, err := readRecord(c.packetReader)
	if err != nil {
		return fmt.Errorf("read ServerFinish: %w", err)
	}
	if err := sfRecord.decrypt(trafficKey, c.serverSeqNum); err != nil {
		return fmt.Errorf("decrypt ServerFinish: %w", err)
	}

	sf, err := ReadServerFinish(sfRecord.data)
	if err != nil {
		return fmt.Errorf("parse ServerFinish: %w", err)
	}

	sfKey := make([]byte, 32)
	hkdf.Expand(
		sha256.New,
		comKey,
		buildHkdfInfo("server finished", nil)).Read(sfKey)

	securityParam := computeHmac(sfKey, c.handshakeHasher.Sum(nil))
	if !bytes.Equal(sf.data, securityParam) {
		return errors.New("ServerFinish verification failed")
	}

	c.serverSeqNum++

	// No ClientFinish for short-link (connection ends here)
	atomic.StoreInt32(&c.status, 1)

	log.Info("Short-link ECDHE handshake complete")

	return nil
}

func (c *MMTLSClientShort) ensureSession(host string) error {
	if c.Session != nil {
		return nil
	}
	return c.Handshake(host)
}

func (c *MMTLSClientShort) Request(host, path string, req []byte) ([]byte, error) {
	if err := c.ensureSession(host); err != nil {
		return nil, fmt.Errorf("ensure session: %w", err)
	}

	log.Info("0-RTT PSK request")

	conn, err := net.Dial("tcp", net.JoinHostPort(host, "80"))
	if err != nil {
		return nil, err
	}
	c.conn = conn

	// Reset seq nums for new 0-RTT request
	c.handshakeHasher.Reset()
	c.clientSeqNum = 0
	c.serverSeqNum = 0

	httpPacket, err := c.packHttp(host, path, req)
	if err != nil {
		return nil, err
	}

	_, err = c.conn.Write(httpPacket)
	if err != nil {
		return nil, err
	}
	response, err := c.parseResponse(c.conn)
	if err != nil {
		return nil, err
	}
	log.Debugf("Receive response:\n%s\n", hex.Dump(response))

	c.packetReader = bytes.NewReader(response)

	if err := c.readServerHello(); err != nil {
		return nil, err
	}

	// trafffic key
	trafficKey, err := c.computeTrafficKey(
		c.Session.pskAccess,
		buildHkdfInfo("handshake key expansion", c.handshakeHasher))
	if err != nil {
		return nil, err
	}
	c.Session.appKey = trafficKey

	if err := c.readServerFinish(); err != nil {
		return nil, err
	}

	dataRecord, err := c.readDataRecord()
	if err != nil {
		return nil, err
	}

	if err := c.readAbort(); err != nil {
		return nil, err
	}

	return dataRecord.data, nil
}

func (c *MMTLSClientShort) Close() error {
	if c.conn != nil {
		log.Debug("Close connection...")
		return c.conn.Close()
	}
	return nil
}

func (c *MMTLSClientShort) handshakeComplete() bool {
	return atomic.LoadInt32(&c.status) == 1
}

func (c *MMTLSClientShort) reset() {
	c.handshakeHasher.Reset()
	c.clientSeqNum = 0
	c.serverSeqNum = 0
}

func (c *MMTLSClientShort) packHttp(host, path string, req []byte) ([]byte, error) {
	tlsPayload := make([]byte, 0)

	datPart, err := c.genDataPart(host, path, req)
	if err != nil {
		return nil, err
	}

	// ClientHello
	hello := newPskZeroHello(&c.Session.tk.tickets[0])
	helloPart := hello.serialize()

	c.handshakeHasher.Write(helloPart)

	earlyKey, _ := c.earlyDataKey(c.Session.pskAccess)

	tlsPayload = append(tlsPayload, createSystemRecord(helloPart).serialize()...)
	c.clientSeqNum++

	// Extensions
	extensionsPart := []byte{
		0x00, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00,
		0x0b, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x12,
		0x00, 0x00, 0x00, 0x00,
	}
	binary.BigEndian.PutUint32(extensionsPart[16:], hello.timestamp)

	c.handshakeHasher.Write(extensionsPart)

	extensionsRecord := createSystemRecord(extensionsPart)
	extensionsRecord.encrypt(earlyKey, c.clientSeqNum)

	tlsPayload = append(tlsPayload, extensionsRecord.serialize()...)
	c.clientSeqNum++

	// Request
	requestRecord := createRawDataRecord(datPart)
	requestRecord.encrypt(earlyKey, c.clientSeqNum)

	tlsPayload = append(tlsPayload, requestRecord.serialize()...)
	c.clientSeqNum++

	// Abort
	abortPart := []byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01}
	abortRecord := createAbortRecord(abortPart)
	abortRecord.encrypt(earlyKey, c.clientSeqNum)

	tlsPayload = append(tlsPayload, abortRecord.serialize()...)
	c.clientSeqNum++

	// HTTP header
	header, err := c.buildRequestHeader(host, len(tlsPayload))
	if err != nil {
		return nil, err
	}

	return append(header, tlsPayload...), nil
}

func (c *MMTLSClientShort) genDataPart(host, path string, req []byte) ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := writeU16LenData(buf, []byte(path)); err != nil {
		return nil, err
	}
	if err := writeU16LenData(buf, []byte(host)); err != nil {
		return nil, err
	}
	if err := writeU32LenData(buf, req); err != nil {
		return nil, err
	}

	data := buf.Bytes()
	pkt := make([]byte, 4)
	binary.BigEndian.PutUint32(pkt, uint32(len(data)))
	pkt = append(pkt, data...)

	return pkt, nil
}

func (c *MMTLSClientShort) buildRequestHeader(host string, length int) ([]byte, error) {
	request := &http.Request{
		Method:     http.MethodPost,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      false,
		Header:     map[string][]string{},
	}

	randName := make([]byte, 4)
	if _, err := rand.Read(randName); err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "*/*")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Connection", "Keep-Alive")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Content-Length", fmt.Sprintf("%d", length))
	request.Header.Set("Upgrade", "mmtls")
	request.Header.Set("User-Agent", "MicroMessenger Client")
	request.URL, _ = url.Parse(fmt.Sprintf("https://%s/mmtls/%x", host, randName))

	b, err := httputil.DumpRequest(request, false)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (c *MMTLSClientShort) parseResponse(conn net.Conn) ([]byte, error) {
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)
	io.Copy(b, resp.Body)
	defer resp.Body.Close()

	return b.Bytes(), nil
}

func (c *MMTLSClientShort) readServerHello() error {
	serverHelloRecord, err := readRecord(c.packetReader)
	if err != nil {
		return err
	}

	c.handshakeHasher.Write(serverHelloRecord.data)
	c.serverSeqNum++

	return nil
}

func (c *MMTLSClientShort) readServerFinish() error {
	record, err := readRecord(c.packetReader)
	if err != nil {
		return err
	}

	if err := record.decrypt(c.Session.appKey, c.serverSeqNum); err != nil {
		return err
	}

	// TODO: verify server finished
	c.serverSeqNum++

	return nil
}

func (c *MMTLSClientShort) readDataRecord() (*mmtlsRecord, error) {
	record, err := readRecord(c.packetReader)
	if err != nil {
		return nil, err
	}

	if err := record.decrypt(c.Session.appKey, c.serverSeqNum); err != nil {
		return nil, err
	}

	c.serverSeqNum++

	return record, nil
}

func (c *MMTLSClientShort) readAbort() error {
	record, err := readRecord(c.packetReader)
	if err != nil {
		return err
	}

	if err := record.decrypt(c.Session.appKey, c.serverSeqNum); err != nil {
		return err
	}

	c.serverSeqNum++

	return nil
}

func (c *MMTLSClientShort) earlyDataKey(pskAccess []byte) (*trafficKeyPair, error) {
	trafficKey := make([]byte, 28)

	if _, err := hkdf.Expand(sha256.New, pskAccess,
		buildHkdfInfo("early data key expansion", c.handshakeHasher)).
		Read(trafficKey); err != nil {
		return nil, err
	}

	// early data key expansion
	pair := &trafficKeyPair{}
	pair.clientKey = trafficKey[:16]
	pair.clientNonce = trafficKey[16:]

	return pair, nil
}

func (c *MMTLSClientShort) computeTrafficKey(shareKey, info []byte) (*trafficKeyPair, error) {
	return computeTrafficKeyN(shareKey, info, 28)
}
