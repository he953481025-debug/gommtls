package main

import (
	"sync"
	"time"

	"github.com/duo/gommtls/mmtls"
	"github.com/duo/gommtls/utils"
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

		if session, err := mmtls.LoadSession("session_long"); err == nil {
			client.Session = session
		}

		if err := client.Handshake("szlong.weixin.qq.com:8080"); err != nil {
			panic(err)
		}

		if client.Session != nil {
			client.Session.Save("session_long")
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

		// Try to load short-link's own session
		if session, err := mmtls.LoadSession("session_short"); err == nil {
			client.Session = session
		}

		defer client.Close()

		// Request() will auto-handshake if no session exists
		response, err := client.Request(
			"dns.weixin.qq.com.cn",
			"/cgi-bin/micromsg-bin/newgetdns",
			nil,
		)
		if err != nil {
			panic(err)
		}

		// Save short-link session for future 0-RTT
		if client.Session != nil {
			client.Session.Save("session_short")
		}

		utils.ParseHTTPResponseFromByte(response)

		wg.Wait()
	}
}
