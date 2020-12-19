package main

import (
	"io"
	"log"
	"net"
	"net/url"
	"net/http"
	"fmt"
	"flag"
)

const bufmax = 1 << 20
var addr = flag.String("addr", "gungfusocksweb.cfapps.io:4443", "https service address")
//var addr = flag.String("addr", "127.0.0.1:8080", "http service address")

func handleconnection(conn net.Conn) {
	//first handshark
	var buf[bufmax]byte
	n, err :=conn.Read(buf[0:bufmax])
	r :=
	
	//second handshark

	//go read from conn and POST to server

	//go GET from server and write to conn
}

func tun2remote(conn net.Conn, conn_ws *websocket.Conn) {
	var buf [bufmax]byte
	if conn == nil || conn_ws == nil {
		return
	}
	for {
		n, err :=conn.Read(buf[0:bufmax])
		if err != nil {
			fmt.Println(err)
			conn.Close()
			conn_ws.Close()
			return
		}
		conn_ws.WriteMessage(websocket.BinaryMessage, buf[0:n])
	}
}

func tun2local(conn_ws *websocket.Conn, conn net.Conn) {
	if conn == nil || conn_ws == nil {
		return
	}
	for {
		_, message, err := conn_ws.ReadMessage()
		if err != nil {
			fmt.Println(err)
			conn_ws.Close()
			conn.Close()
			return
		}
		_, err = conn.Write(message[0:])
	}
}

func main() {
	// Listen on TCP port 1080 on all interfaces.
	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
			continue
		}
		//handleconnection
		go handleconnection(conn)
	}
}
