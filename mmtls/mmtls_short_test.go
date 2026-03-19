package mmtls

import (
	"testing"

	"github.com/duo/gommtls/utils"
)

func TestShortLinkECDHEHandshake(t *testing.T) {
	client := NewMMTLSClientShort()

	err := client.Handshake("dns.weixin.qq.com.cn")
	if err != nil {
		t.Fatalf("Short-link ECDHE handshake failed: %v", err)
	}
	t.Log("Short-link ECDHE handshake success")

	if client.Session == nil {
		t.Fatal("Session should not be nil after handshake")
	}
	if client.Session.pskAccess == nil {
		t.Fatal("pskAccess should not be nil after handshake")
	}
	if client.Session.pskRefresh == nil {
		t.Fatal("pskRefresh should not be nil after handshake")
	}
	if client.Session.tk == nil || len(client.Session.tk.tickets) == 0 {
		t.Fatal("Session tickets should not be empty after handshake")
	}
	t.Logf("Session has %d tickets", len(client.Session.tk.tickets))
}

func TestShortLinkAutoHandshake(t *testing.T) {
	client := NewMMTLSClientShort()
	// No session loaded — Request() should auto-handshake

	respBody, err := client.Request("dns.weixin.qq.com.cn",
		"/cgi-bin/micromsg-bin/newgetdns",
		nil)
	if err != nil {
		t.Fatalf("Short-link auto-handshake + request failed: %v", err)
	}
	t.Log("Short-link auto-handshake + request success")

	_, err = utils.ParseHTTPResponseFromByte(respBody)
	if err != nil {
		t.Fatalf("Parse response body failed: %v", err)
	}
	t.Log("Parse response body success")
}

func TestShortLinkHandshakeThenRequest(t *testing.T) {
	client := NewMMTLSClientShort()

	// Step 1: Explicit handshake
	err := client.Handshake("dns.weixin.qq.com.cn")
	if err != nil {
		t.Fatalf("Short-link ECDHE handshake failed: %v", err)
	}
	t.Log("Short-link ECDHE handshake success")

	// Step 2: 0-RTT request using the session from handshake
	respBody, err := client.Request("dns.weixin.qq.com.cn",
		"/cgi-bin/micromsg-bin/newgetdns",
		nil)
	if err != nil {
		t.Fatalf("Short-link 0-RTT request failed: %v", err)
	}
	t.Log("Short-link 0-RTT request success")

	_, err = utils.ParseHTTPResponseFromByte(respBody)
	if err != nil {
		t.Fatalf("Parse response body failed: %v", err)
	}
	t.Log("Parse response body success")
}

func TestShortLinkSessionPersistence(t *testing.T) {
	sessionPath := "../session_short_test"

	// Step 1: Handshake and save session
	client1 := NewMMTLSClientShort()
	err := client1.Handshake("dns.weixin.qq.com.cn")
	if err != nil {
		t.Fatalf("Short-link ECDHE handshake failed: %v", err)
	}
	t.Log("Short-link ECDHE handshake success")

	err = client1.Session.Save(sessionPath)
	if err != nil {
		t.Fatalf("Save session failed: %v", err)
	}
	t.Log("Session saved")

	// Step 2: Load session and make 0-RTT request
	client2 := NewMMTLSClientShort()
	session, err := LoadSession(sessionPath)
	if err != nil {
		t.Fatalf("Load session failed: %v", err)
	}
	client2.Session = session
	t.Log("Session loaded")

	respBody, err := client2.Request("dns.weixin.qq.com.cn",
		"/cgi-bin/micromsg-bin/newgetdns",
		nil)
	if err != nil {
		t.Fatalf("Short-link 0-RTT request with loaded session failed: %v", err)
	}
	t.Log("Short-link 0-RTT request with loaded session success")

	_, err = utils.ParseHTTPResponseFromByte(respBody)
	if err != nil {
		t.Fatalf("Parse response body failed: %v", err)
	}
	t.Log("Parse response body success")
}

func Test0RttPskSendData(t *testing.T) {
	client := NewMMTLSClientShort()
	session, err := LoadSession("../session_short")
	if err != nil {
		t.Fatalf("mmtls short client 0rtt psk load session failed %v", err)
	}
	t.Log("mmtls short client 0rtt psk load success")
	client.Session = session
	respBody, err := client.Request("dns.weixin.qq.com.cn",
		"/cgi-bin/micromsg-bin/newgetdns",
		nil)
	if err != nil {
		t.Fatalf("mmtls short client 0rtt psk send request failed %v", err)
	}
	t.Log("mmtls short client 0rtt psk send request success")
	_, err = utils.ParseHTTPResponseFromByte(respBody)
	if err != nil {
		t.Fatalf("mmtls short client 0rtt psk parse request body failed %v", err)
	}
	t.Log("mmtls short client 0rtt psk parse response body success")
}
