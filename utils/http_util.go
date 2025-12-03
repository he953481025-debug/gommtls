package utils

import 
(
	"net/http"
	"fmt"
	"io"
	"bufio"
	"bytes"
	"compress/flate"
)

func ParseHTTPResponseFromByte(data []byte) (*http.Response, error) {
	// 2. 使用net/http解析响应
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		fmt.Printf("parse http response error: %v", err)
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
