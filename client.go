package main

import (
	"bytes"
	"fmt"
	"io"
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

const bufmax = 1 << 20

//var addr = flag.String("addr", "gungfusocksweb.cfapps.io:4443", "https service address")

//var addr = flag.String("addr", "127.0.0.1:8080", "http service address")

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

	conn.Read(recvbuf[0:bufmax]) //读取客户端请求包

	req.ver = recvbuf[0]
	req.cmd = recvbuf[1]
	req.rsv = recvbuf[2]
	req.atyp = recvbuf[3]

	if req.atyp != 0x01 {
		//地址类型不接受
		reqret.rep = 0x08
	} else if req.cmd != 0x01 {
		//命令类型不接受
		reqret.rep = 0x07
	} else {
		req.dstaddr[0] = recvbuf[4]
		req.dstaddr[1] = recvbuf[5]
		req.dstaddr[2] = recvbuf[6]
		req.dstaddr[3] = recvbuf[7]
		req.dstport[0] = recvbuf[8]
		req.dstport[1] = recvbuf[9]

		//执行cmd
		fmt.Println("index :", index, "...start to post handshark")
		body := bytes.NewReader(recvbuf[4:10])
		hc := &http.Client{}
		hreq, _ := http.NewRequest("POST", "https://socks-server-758011.asia1.kinto.io/handshark", body)
		//hreq, _ := http.NewRequest("POST", "http://127.0.0.1:8080/handshark", body)
		hreq.Header.Add("x-index-2955", strconv.Itoa(index))
		resp, _ := hc.Do(hreq)
		if resp.StatusCode != 200 {
			reqret.rep = 0x01
		} else {
			resp.Body.Read(httpbody[0:bufmax])
			reqret.rep = 0x00
		}
		fmt.Println("index :", index, "...end to post handshark,the statuscoed is :", resp.StatusCode)
		resp.Body.Close()
	}

	reqret.ver = 0x05
	reqret.rsv = 0x00
	reqret.atyp = 0x01
	reqret.bndaddr[0] = 0x00
	reqret.bndaddr[1] = 0x00
	reqret.bndaddr[2] = 0x00
	reqret.bndaddr[3] = 0x00
	reqret.bndport[0] = 0x00
	reqret.bndaddr[2] = 0x00

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
	if reqret.rep != 0x00 {
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
		fmt.Println("index :", index, "...read from client,the data lenth is :", n)
		if err == io.EOF {
			conn.Close()
			//hc.CloseIdleConnections()
			break
		}
		fmt.Println("index :", index, "...start to post data")
		body := bytes.NewReader(recvbuf[0:n])
		hreq, _ := http.NewRequest("POST", "https://socks-server-758011.asia1.kinto.io/post", body)
		//hreq, _ := http.NewRequest("POST", "http://127.0.0.1:8080/post", body)
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
	hreq, _ := http.NewRequest("GET", "https://socks-server-758011.asia1.kinto.io/get", nil)
	//hreq, _ := http.NewRequest("GET", "http://127.0.0.1:8080/get", nil)
	hreq.Header.Add("x-index-2955", strconv.Itoa(index))
	for {
		if conn == nil {
			fmt.Println("the client conn is closed")
			return
		}
		fmt.Println("index :", index, "...start to get data")
		resp, _ := hc.Do(hreq)
		fmt.Println("index :", index, "...end to get data,the status code is :", resp.StatusCode)
		buf, err := ioutil.ReadAll(resp.Body)
		fmt.Println("index :", index, "...read from remote ,the err is :", err)
		n, err := conn.Write(buf)
		fmt.Println("index :", index, "...send data to client ,the err is :", err, ",the data length is :", n)
		if err != nil {
			conn.Close()
			break
		}
		/*for { //数据量大时，可能一次不能完全读完，所以需要循环读取
			n, _ := resp.Body.Read(sendbuf[0:bufmax])
			if n <= 0 {
				//conn.Close()
				break
			}
			fmt.Println("index :", index, "...send to client,the data lenth is :", n)
			n, _ = conn.Write(sendbuf[0:n])
		}*/
		//n, _ := resp.Body.Read(sendbuf[0:bufmax])
		resp.Body.Close()

		//fmt.Println("index :", index, "...send to client,the data lenth is :", n)
		//n, _ = conn.Write(sendbuf[0:n])
		//if n <= 0 {
		//	conn.Close()
		//	//hc.CloseIdleConnections()
		//	break
		//}
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

func main() {
	// Listen on TCP port 1080 on all interfaces.
	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("start to listen 1080 port")
	defer l.Close()
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
