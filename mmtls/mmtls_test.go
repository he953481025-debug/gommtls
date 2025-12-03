package mmtls

import (
	"testing"

)


func Test1RTTECDHEHandshake(t *testing.T) {
	longLinkClient := NewMMTLSClient()
	err := longLinkClient.Handshake("szlong.weixin.qq.com:8080")
	if err != nil {
		t.Fatalf("1-RTT ECDHE Handshake error %v", err)
	}
	t.Logf("1-RTT ECDHE  handshake success")
	err = longLinkClient.sendNoop()

	if err != nil {
		t.Fatalf("1-RTT ECDHE   send noop error %v", err)
	}
	t.Logf("1-RTT ECDHE  Send noop success")
}

func Test1RTTPskHandshake(t *testing.T) {
	longLinkClient := NewMMTLSClient()
	session, err := LoadSession("../session")
	if err != nil {
		t.Fatalf("1-RTT PSK load session error %v", err)
	}
	longLinkClient.Session = session
	err = longLinkClient.Handshake("szlong.weixin.qq.com:8080")
	if err != nil {
		t.Fatalf("1-RTT PSK Handshake error %v", err)
	}
	t.Logf("1-RTT PSK  handshake success")
	err = longLinkClient.sendNoop()

	if err != nil {
		t.Fatalf("1-RTT PSK   send noop error %v", err)
	}
	t.Logf("1-RTT PSK  Send noop success")
}

