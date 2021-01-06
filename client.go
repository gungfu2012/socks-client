package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
)

type vermsg struct {
	ver     uint8
	nmethod uint8
	methods [255]uint8
} //定义socks5版本包结构-接收

type vermsgret struct {
	ver    uint8
	method uint8
} //定义socks5版本包结构-发送

type reqmsg struct {
	ver     uint8
	cmd     uint8
	rsv     uint8
	atyp    uint8
	dstaddr [4]uint8
	dstport [2]uint8
} //定义socks5请求包结构-接收

type reqmsgret struct {
	ver     uint8
	rep     uint8
	rsv     uint8
	atyp    uint8
	bndaddr [4]uint8
	bndport [2]uint8
} //定义socks5请求包结构-发送

const opdata uint8 = 21 //the xor opdata

const hostnum = 9 //the num of hosts
var hostarray [hostnum]string = [hostnum]string{
			"http://127.0.0.1:8080", "https://socks-server-758011.asia1.kinto.io", "https://socks-server-11138b.us1.kinto.io", "https://socks-server-e4349c.eu1.kinto.io", "https://kintohub-eu.gungfu2012.workers.dev", "https://kintohub-us.gungfu2012.workers.dev", "https://kintohub-as1.gungfu2012.workers.dev", "https://kintohub-as2.gungfu2012.workers.dev", "https://kintohub-as3.gungfu2012.workers.dev"} //the hosts list
var hostname string //the selected server

const bufmax = 1 << 20

//socks5handshark完成socks5协议的握手，返回握手成功与否
func socks5handshark(conn net.Conn, index int) bool {

	var recvbuf [bufmax]byte  //客户端数据接收缓冲区
	var sendbuf [bufmax]byte  //客户端数据发送缓冲区
	var httpbody [bufmax]byte //httpbody缓冲区
	var ver vermsg            //版本包
	var verret vermsgret      //版本响应包
	var req reqmsg            //请求包
	var reqret reqmsgret      //请求响应包

	conn.Read(recvbuf[0:bufmax]) //读取客户端版本包

	verret.ver = 0x05
	verret.method = 0xFF
	ver.ver = recvbuf[0]
	ver.nmethod = recvbuf[1]
	var i uint8
	for i = 0; i < ver.nmethod; i++ {
		ver.methods[i] = recvbuf[i+2]
	}
	if ver.ver != 0x5 {
		return false
	}
	for _, method := range ver.methods {
		if method == 0x00 {
			verret.method = method
			break
		}
	}

	sendbuf[0] = verret.ver
	sendbuf[1] = verret.method
	conn.Write(sendbuf[0:2]) //向客户端发送响应包

	n, _ := conn.Read(recvbuf[0:bufmax]) //读取客户端请求包

	req.ver = recvbuf[0]
	req.cmd = recvbuf[1]
	req.rsv = recvbuf[2]
	req.atyp = recvbuf[3]

	for i := 0; i < n; i++ {
		recvbuf[i] = recvbuf[i] ^ opdata
	}

	var body *bytes.Reader
	var x_atyp string
	fmt.Println("the addr type is :", req.atyp)
	switch req.atyp {
	case 0x01:
		body = bytes.NewReader(recvbuf[4:10])
		x_atyp = "1"
	case 0x03:
		body = bytes.NewReader(recvbuf[5 : 5+(recvbuf[4]^opdata)+2])
		x_atyp = "3"
	case 0x04:
		body = bytes.NewReader(recvbuf[4:22])
		x_atyp = "4"
	}
	switch req.cmd {
	case 0x01:
		fmt.Println("index :", index, "...start to post handshark")
		fmt.Println("the ip and port is :", body)
		hc := &http.Client{}
		hreq, _ := http.NewRequest("POST", hostname+"/handshark", body)
		hreq.Header.Add("x-index-2955", strconv.Itoa(index))
		hreq.Header.Add("x-atyp-2955", x_atyp)
		resp, err := hc.Do(hreq)
		fmt.Println("the error is :", err)
		if resp.StatusCode != 200 {
			reqret.rep = 0x01
		} else {
			resp.Body.Read(httpbody[0:bufmax])
			reqret.rep = 0x00
		}
		fmt.Println("index :", index, "...end to post handshark,the statuscoed is :", resp.StatusCode)
		resp.Body.Close()
	case 0x03:
		reqret.rep = 0x00
	default:
		reqret.rep = 0x07
	}

	reqret.ver = 0x05
	reqret.rsv = 0x00
	reqret.atyp = 0x01
	reqret.bndaddr[0] = 127
	reqret.bndaddr[1] = 0
	reqret.bndaddr[2] = 0
	reqret.bndaddr[3] = 1
	reqret.bndport[0] = 4
	reqret.bndport[1] = 57

	sendbuf[0] = reqret.ver
	sendbuf[1] = reqret.rep
	sendbuf[2] = reqret.rsv
	sendbuf[3] = reqret.atyp
	sendbuf[4] = reqret.bndaddr[0]
	sendbuf[5] = reqret.bndaddr[1]
	sendbuf[6] = reqret.bndaddr[2]
	sendbuf[7] = reqret.bndaddr[3]
	sendbuf[8] = reqret.bndport[0]
	sendbuf[9] = reqret.bndport[1]

	conn.Write(sendbuf[0:10])
	if reqret.rep != 0x00 || req.cmd == 0x03 {
		return false
	}
	return true
}

func post(conn net.Conn, index int) {
	var recvbuf [bufmax]byte //客户端数据接收缓冲区
	//var sendbuf [bufmax]byte  //客户端数据发送缓冲区
	//var httpbody [bufmax]byte //httpbody缓冲区
	hc := &http.Client{}
	for {
		if conn == nil {
			fmt.Println("the client conn is closed")
			return
		}
		n, err := conn.Read(recvbuf[0:bufmax])
		fmt.Println("index :", index, "...read from client,the data lenth is :", n, "the error is :", err)
		if err != nil {
			conn.Close()
			//hc.CloseIdleConnections()
			break
		}
		if n == 0 {
			//time.Sleep(100 * time.Millisecond)
			continue
		}
		fmt.Println("index :", index, "...start to post data")
		for i := 0; i < n; i++ {
			recvbuf[i] = recvbuf[i] ^ opdata
		}
		body := bytes.NewReader(recvbuf[0:n])
		hreq, _ := http.NewRequest("POST", hostname+"/post", body)
		hreq.Header.Add("x-index-2955", strconv.Itoa(index))
		resp, _ := hc.Do(hreq)
		fmt.Println("index :", index, "...end to post data,the status code is :", resp.StatusCode)
		resp.Body.Close()
	}
}

func get(conn net.Conn, index int) {
	//var recvbuf [bufmax]byte //客户端数据接收缓冲区
	//var sendbuf [bufmax]byte //客户端数据发送缓冲区
	//var httpbody [bufmax]byte //httpbody缓冲区
	hc := &http.Client{}
	hreq, _ := http.NewRequest("GET", hostname+"/get", nil)
	hreq.Header.Add("x-index-2955", strconv.Itoa(index))
	for {
		if conn == nil {
			fmt.Println("the client conn is closed")
			return
		}
		fmt.Println("index :", index, "...start to get data")
		resp, _ := hc.Do(hreq)
		if resp.StatusCode == http.StatusBadRequest {
			resp.Body.Close()
			conn.Close()
			break
		}
		fmt.Println("index :", index, "...end to get data,the status code is :", resp.StatusCode)
		buf, err := ioutil.ReadAll(resp.Body)
		fmt.Println("index :", index, "...read from remote ,the err is :", err)
		n := len(buf)
		for i := 0; i < n; i++ {
			buf[i] = buf[i] ^ opdata
		}
		n, err = conn.Write(buf)
		fmt.Println("index :", index, "...send data to client ,the err is :", err, ",the data length is :", n)
		if err != nil {
			conn.Close()
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}
}
func handleconnection(conn net.Conn, index int) {
	//socks5handshark
	ret := socks5handshark(conn, index)
	//fmt.Println(ret)
	if ret != true {
		conn.Close()
		return
	}

	//go read from conn and POST to server
	go post(conn, index)

	//go GET from server and write to conn
	go get(conn, index)
}

func handleudp(lp net.PacketConn) {
	var buf [bufmax]byte
	for {
		n, addr, _ := lp.ReadFrom(buf[0:bufmax])
		fmt.Println("got udp data,the length is :", n)
		if n <= 0 {
			continue
		}
		go postudp(lp, addr, buf[0:n])
	}

}

func postudp(lp net.PacketConn, addr net.Addr, data []byte) {
	var headerlen = 0
	hc := &http.Client{}
	switch data[3] {
	case 0x01:
		headerlen = 0x0A
		fmt.Println("udp data is ipv4")
	case 0x04:
		headerlen = 0x16
		fmt.Println("udp data is ipv6")
	default:
		//headerlen = (7 + data[4])
		fmt.Println("udp data is domain")
	}
	n := len(data)
	for i := 0; i < n; i++ {
		data[i] = data[i] ^ opdata
	}

	body := bytes.NewReader(data[headerlen:])
	hreq, _ := http.NewRequest("POST", hostname+"/dns", body)
	resp, _ := hc.Do(hreq)
	buf, _ := ioutil.ReadAll(resp.Body)
	var sendbuf [bufmax]byte
	for i := 0; i < headerlen; i++ {
		sendbuf[i] = data[i]
	}
	n = len(buf)
	for i := headerlen; i-headerlen < n; i++ {
		sendbuf[i] = buf[i-headerlen]
	}
	for i := 0; i < headerlen+n; i++ {
		sendbuf[i] = sendbuf[i] ^ opdata
	}
	lp.WriteTo(sendbuf[0:headerlen+len(buf)], addr)
}

func main() {
	for i := 0; i < hostnum; i++ {
		fmt.Println("index : ", i)
		fmt.Println(hostarray[i])
	}
	fmt.Println("select the server by input the index:")
	var serverindex int
	fmt.Scanf("%d", &serverindex)
	hostname = hostarray[serverindex]
	fmt.Println("the selected server is : ", hostarray[serverindex])
	// Listen on TCP port 1080 on all interfaces.
	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("start to listen 1080 port")
	defer l.Close()
	lp, err := net.ListenPacket("udp", ":1081")
	if err != nil {
		log.Fatal(err)
	}
	go handleudp(lp)
	fmt.Println("start to listen udp 1081 port")
	defer lp.Close()
	var index int
	index = 0
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
			conn.Close()
			continue
		}
		//handleconnection
		fmt.Println("got a connection from client, the index is :", index)
		go handleconnection(conn, index)
		index = (index + 1) % 65536
	}
}
