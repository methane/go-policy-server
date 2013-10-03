package main

import (
	"log"
	"net"
	"time"
)

var POLICY string = `<?xml version="1.0" encoding="UTF-8"?>
<cross-domain-policy xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:noNamespaceSchemaLocation="http://www.adobe.com/xml/schemas/PolicyFileSocket.xsd">
<allow-access-from domain="*" to-ports="*" secure="false" />
<site-control permitted-cross-domain-policies="master-only" />
</cross-domain-policy>`

func serve(con net.Conn) (err error) {
	var read_bytes int = 0

	con.SetWriteDeadline(3 * time.SECOND * 3)
	buf := make([]byte, 64)

	defer con.Close()
	for {
		log.Printf("Connected: %s", con.RemoteAddr().String())
		n, e := con.Read(buf[read_bytes:])
		if e != nil {
			return e
		}
		read_bytes += n
		if buf[read_bytes-1] != 0 {
			if read_bytes >= 62 {
				log.Printf("Invalid request from %s: no NUL byte", con.RemoteAddr().String())
				return error("Invalid Request")
			}
		} else {
			break
		}
	}
	req := string(buf[:read_bytes-1])
	if req != "<policy-file-request />" {
		log.Printf("Invalid request from %s: req=%s", con.RemoteAddr().String(), req)
		return NewError("Invalid Request")
	}

	_, e := con.Write([]byte(POLICY))
	if e == nil {
		log.Printf("Success to send response to %s", con.RemoteAddr().String())
	} else {
		log.Printf("Failed to send response to %s", con.RemoteAddr().String())
	}
	return e
}

func main() {
	l, e := net.Listen("tcp", ":843")
	if e != nil {
		log.Printf("Failed to listen: %s", e.String())
		return
	}
	for {
		rw, e := l.Accept()
		if e != nil {
			log.Printf("Failed to Accept: %s", e.String())
			return
		}
		go serve(rw)
	}
}
