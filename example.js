import * as wolfssl from "quickjs-wolfssl.so";
import * as net from "net.so";
import * as std from "std";
import * as os from "os";

function uint8arrayToString(arr)
{
	const enc = String.fromCharCode.apply(null, arr);
	const dec = decodeURIComponent(escape(enc));
	return dec;
}

function stringToUint8array(str)
{
	const encstr = unescape(encodeURIComponent(str));
	const chrlist = encstr.split('');
	const arr = chrlist.map( ch => ch.charCodeAt(0) );
	return new Uint8Array(arr);
}

function runTests()
{
	const testString = 'Well I met an old man dying on a train. No more destination, no more pain. Well he said one thing: "Before I graduate never let your fear decide your fate"';
	
	const data = stringToUint8array(testString);
	console.log(`Original: ${testString}`);

	const asB64 = wolfssl.toBase64(data.buffer);
	console.log(`Base64 => ${asB64}`);
	
	const fromB64 = wolfssl.fromBase64(asB64);
	console.log(`Base64 <= ${uint8arrayToString(fromB64)}`);

	const md5sum = wolfssl.md5sum(data.buffer);
	console.log(`MD5 should be bdc20bf28ed988c221cb6cfa2b417b08, got ${md5sum}`);
	
	const sha256sum = wolfssl.sha256sum(data.buffer);
	console.log(`SHA256 should be 4a4c36949311dfbe0cae22f498e0e4d7b714a38392681e8aff5620721aa6d98e, got ${sha256sum}`);
}

function runTLSServer(sinfo)
{
	const serverfd = net.socket(sinfo.family, 'stream');
	try {
		if( !net.bind(serverfd, sinfo.family, sinfo.ip, sinfo.port) )
		{
			console.log('failed to bind');
			std.exit(-1);
		}
	} catch(err) {
		console.log("bind: "+err);
		std.exit(-1);
	}

	try {
		if( !net.listen(serverfd, 10) )
		{
			console.log('failed to listen');
			std.exit(-1);
		}
	} catch(err) {
		console.log("listen: "+err);
		std.exit(-1);
	}

	os.setReadHandler(serverfd, function() {
		let info;
		try {
			info = net.accept(serverfd);
			console.log(`Connection from ${info.family}:[${info.ip}]:${info.port}`);
		} catch(err) {
			console.log("accept: "+err);
			//std.exit(-1);
		}

		try {
			info.tlsSocket = sinfo.tls.wrap(info.fd);
			info.write = function(data)
			{
				if( !this.tlsSocket )
					return;

				try {
					return this.tlsSocket.write(data);
				} catch(err) {
					console.log("tlsSocket.write error: "+err);
				}
			};
			info.close = function()
			{
				console.log("Closing connection...");
				os.setReadHandler(info.fd, null);
				os.close(this.fd);
				console.log("Closed.");
				delete this.tlsSocket;

				std.gc();
			};
			info.readHandler = function(data)
			{
                const asstr = uint8arrayToString(data);
				console.log("Read: "+asstr);

				const content = `<html><body><h1>It works.</h1><br><img src="http://localhost:8081/tmp/tmp6v8kzb3v.png" /></body></html>`;
				const pkt = stringToUint8array(`HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: ${content.length}\r\n\r\n${content}`);
				this.write(pkt.buffer);
				this.close();
			};
			setupTLSClient(info);
		} catch(ierr) {
			console.log("setup: "+ierr);
			os.setReadHandler(info.fd, null);
			os.close(info.fd);
		}
	});

	try {
		sinfo.tls = wolfssl.tlsServer('certs/testing.crt', 'certs/testing.key');
	} catch(err) {
		console.log("tlsServer error: "+err);
	}

	console.log(`Listening on ${sinfo.family}:[${sinfo.ip}]:${sinfo.port}`);
	return serverfd;
}

function setupTLSClient(info)
{
    console.log(`info: ${JSON.stringify(info,null,2)}`);

    os.setReadHandler(info.fd, function() {
		if( !info.handshakeComplete )
		{
			try {
				const ret = info.tlsSocket.accept();
				info.handshakeComplete = true;
				console.log("Handshake completed...");
			} catch(err) {
				console.log("tlsSocket.accept error: "+err);
				os.setReadHandler(info.fd, null);
				os.close(info.fd);
			}
			return;
		}

        let data = new Uint8Array(8192);
        try {
			const br = info.tlsSocket.read(data.length);
            //const br = os.read(info.fd, data.buffer, 0, data.length);
            if( !br ) {
                console.log("read error");
				os.close(info.fd);
                os.setReadHandler(info.fd, null);
                return;
            }
            else if( br.length === 0 )
            {
                console.log(`Connection closed from ${info.family}:[${info.ip}]:${info.port}`);
                os.setReadHandler(info.fd, null);
                return;
            }
            else
				return info.readHandler(br);
        } catch(err) {
            console.log("readhandler: "+err);
            os.setReadHandler(info.fd, null);
        }
    });
}
//runTests();

const sinfo = { 'family':'inet6', 'ip':'::', 'port':8082 };
runTLSServer(sinfo);
/*
std.gc();

std.exit(0);
*/
