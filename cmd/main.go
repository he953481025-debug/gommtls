package main

import (
	// "encoding/hex"
	"bufio"
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/duo/gommtls/mmtls"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(log.DebugLevel)
}

func main() {


	{
		client := mmtls.NewMMTLSClient()

		defer client.Close()

		if session, err := mmtls.LoadSession("session"); err == nil {
			client.Session = session
		}

		if err := client.Handshake("szlong.weixin.qq.com:8080"); err != nil {
			panic(err)
		}

		if client.Session != nil {
			client.Session.Save("session")
		}
		for {
			if err := client.Noop(); err != nil {
				panic(err)
			}
			time.Sleep(time.Duration(30) * time.Second)
		}

	}

	// {
	// 	client := mmtls.NewMMTLSClientShort()

	// 	if session, err := mmtls.LoadSession("session"); err == nil {
	// 		client.Session = session
	// 	}

	// 	defer client.Close()

	// 	response, err := client.Request(
	// 		"dns.weixin.qq.com.cn",
	// 		"/cgi-bin/micromsg-bin/newgetdns",
	// 		nil,
	// 	)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	// log.Debugf("Response:\n%s\n", hex.Dump(response))

	// 	parseHTTPResponseFromHex(response)
	// }
}

func parseHTTPResponseFromHex(data []byte) (*http.Response, error) {
	// 2. 使用net/http解析响应
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		log.Errorf("parse http response error: %v", err)
		return nil, err
	}
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("StatusCode: %d\n", resp.StatusCode)
	fmt.Printf("Proto: %s\n", resp.Proto)
	respHeaders := resp.Header
	for key, value := range respHeaders {
		fmt.Printf("Header: %s: %v\n", key, value)
	}

	var reader io.ReadCloser
	// 处理 deflate 压缩
	if resp.Header.Get("Content-Encoding") == "deflate" {
		reader = flate.NewReader(resp.Body)
	} else {
		reader = resp.Body
	}

	// 读取响应体
	body, _ := io.ReadAll(reader)
	fmt.Printf("Body: %s\n", body)

	defer resp.Body.Close()

	return resp, nil
}
