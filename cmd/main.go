package main

import (
	// "encoding/hex"
	// "bufio"
	// "bytes"
	// "compress/flate"
	// "fmt"
	// "io"
	// "net/http"
	"sync"
	"time"
	"github.com/duo/gommtls/utils"
	"github.com/duo/gommtls/mmtls"
	log "github.com/sirupsen/logrus"
)

var wg sync.WaitGroup

func init() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(log.DebugLevel)

	wg.Add(1)
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

		go func() {
			defer wg.Done()
			for {
				if err := client.Noop(); err != nil {
					panic(err)
				}
				time.Sleep(time.Duration(30) * time.Second)
			}
		}()	
	}

	{
		client := mmtls.NewMMTLSClientShort()

		if session, err := mmtls.LoadSession("session"); err == nil {
			client.Session = session
		}

		defer client.Close()

		response, err := client.Request(
			"dns.weixin.qq.com.cn",
			"/cgi-bin/micromsg-bin/newgetdns",
			nil,
		)
		if err != nil {
			panic(err)
		}

		// log.Debugf("Response:\n%s\n", hex.Dump(response))
		
		utils.ParseHTTPResponseFromByte(response)
		// parseHTTPResponseFromByte(response)
		
		wg.Wait()
	}
}

