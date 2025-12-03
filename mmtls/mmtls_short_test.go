package mmtls

import (
	"testing"
	"github.com/duo/gommtls/utils"
)


func Test0RttPskSendData(t *testing.T) {
	client := NewMMTLSClientShort()
	session, err := LoadSession("../session")
	if err != nil {
		t.Fatalf("mmtls short client 0rtt psk load session failed %v", err)
	}
	t.Log("mmtls short client 0rtt psk load success")
	client.Session = session
	respBody, err := client.Request("dns.weixin.qq.com.cn",
			"/cgi-bin/micromsg-bin/newgetdns",
			nil,)
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