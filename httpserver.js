import * as wolfssl from "quickjs-wolfssl.so";
import * as net from "net.so";
import * as std from "std";
import * as os from "os";

const webroot = 'webroot';

function uint8arrayToString(arr)
{
/***
 * Pure JS version, works, but not super fast:
 ***
	const enc = String.fromCharCode.apply(null, arr);
	const dec = decodeURIComponent(escape(enc));
	return dec;
*/
	return wolfssl.uint8ArrayToString( arr.buffer );
}

function stringToUint8array(str)
{
/***
 * Pure JS version, works, but not super fast:
 ***
	let buf = new ArrayBuffer(str.length);
	let bufView = new Uint8Array(buf);
	const strLen = str.length;
	for (let i=0; i<strLen; i++) {
		bufView[i] = str.charCodeAt(i);
	}
	return bufView;
*/
	return new Uint8Array( wolfssl.stringToUint8Array(str) );
}

function bytesToSize(bytes) {
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  if (bytes === 0) return 'n/a'
  const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)), 10)
  if (i === 0) return `${bytes} ${sizes[i]}`
  return `${(bytes / (1024 ** i)).toFixed(1)} ${sizes[i]}`
}

function sendFileChunk(info, headerBuffer)
{
	if( !info )
	{
		console.log("sendFileChunk: no info!");
		return;
	}

	let data = new Uint8Array(8192);
	let bp = 0;
	if( headerBuffer )
	{
		let x=0;
		for( x=0; x < headerBuffer.length; x++ )
			data[x] = headerBuffer[x];
		bp = x;
		//info.write(newbuf.buffer);
	}

	try {
		const br = os.read(info.file, data.buffer, bp, data.length-bp);
		if( 0 == br )
		{
			os.setReadHandler(info.file, null);
			os.close(info.file);
			if( info.sendComplete )
			{
				info.sendComplete();
				delete info.sendComplete;
			}

			info.flush();
			//info.close();
			return;
		}

		info.write(data.buffer, br+bp);
	} catch(err) {
		console.log("sendfile: "+err);
		console.log( new Error().stack );
		os.setReadHandler(info.file, null);
		os.close(info.file);
		info.close();
	}
}

function sendFile(info, path, mimetype)
{
	const [obj, err] = os.stat(path);
	if( !( obj.mode & os.S_IFREG ) )
	{
		console.log(' -- Not a file -- ');
		return;
	}

	let headers = [
		`Connection: ${info.connectionState}`,
		`Content-Type: ${mimetype}`,
		`Content-Length: ${obj.size}`,
		`Date: ${getHTTPDate( new Date() )}`
	];

	info.file = os.open(path, os.O_RDONLY);
	const asstr = `${info.proto} 200 Okay\r\n${headers.join("\r\n")}\r\n\r\n`;
	let newbuf = stringToUint8array(asstr);

	// Stop processing requests until send finishes~
	console.log("Disabling read handler...");
	info.transmitting = true;
	info.sendComplete = function() {
		delete info.transmitting;
		if( info.receiveMore )
		{
			info.receiveMore();
			delete info.receiveMore;
		}
	};

	os.setReadHandler(info.file, function() {
		sendFileChunk(info, newbuf);
		newbuf = false;
	});
}

function sendContent(info, content, mimetype, fullstatus)
{
	if( !fullstatus )
		fullstatus = '200 OK';

	let headers = [
		`Connection: ${info.connectionState}`,
		`Content-Type: ${mimetype}`,
		`Content-Length: ${content.length}`,
		`Date: ${getHTTPDate( new Date() )}`
	];

	const asstr = `${info.proto} ${fullstatus}\r\n${headers.join("\r\n")}\r\n\r\n${content}`;
	const start = new Date();
	const newbuf = stringToUint8array(asstr);
	console.log("sendContent:stringToUint8array "+( (new Date().getTime()) - start.getTime() )+"ms");
	info.write(newbuf.buffer);
}

function send404(info)
{
	console.log(" xxx Sending 404...");
	console.log( new Error().stack );
	const content = "<html><head><title>404 - Not Found</title></head><body><h2>Sorry, resource not found.</h2></body></html>";
	sendContent(info, content, 'text/html', '404 Not Found');
}

function handleRequest(info, lines)
{
	const req = lines[0].split(' ');

	console.log("Request: "+req[1]);
	info.proto = req[2];

	info.connectionState = 'keep-alive';
	if( info.proto === 'HTTP/1.0' )
		info.connectionState = 'close';

	// Look through headers because enh why not:
	for( const l of lines )
	{
		const pair = l.split(': ');
		if( pair[0] === 'Connection' )
			info.connectionState = pair[1];
	}

	if( !req || req.length < 3 )
		return;

	let root = webroot;
	if( req[1].substr(0, 10) === '/internal/' )
		root = '.';

	sendResource(info, root, req[1]);

	if( info.connectionState === 'close' )
	{
		info.flush();
		info.close();
	}

	//std.gc();
}

function handlePacket(info, pkt)
{
	let raw = info.prevContent ? info.prevContent + pkt : pkt;

	let lines = [];
	let start = new Date();
	let letters = raw.split('');
	console.log("handlePacket:split took "+( (new Date().getTime()) - start.getTime() )+"ms");

	let line = new Array(256);
	let lpos = 0;
	start = new Date();
	for( let x=0, y=letters.length; x < y; x++ )
	{
		const l = letters[x];
		if( l === "\n" )
		{
			if( lpos === 0 )
			{
				console.log("handlePacket:proc took "+( (new Date().getTime()) - start.getTime() )+"ms");

				// process this.
				info.prevContent = raw.substr(x+1);
				start = new Date();
				handleRequest(info, lines);
				console.log("handlePacket took "+( (new Date().getTime()) - start.getTime() )+"ms");

				if( info.prevContent.length > 1 )
				{
					if( info.transmitting )
					{
						info.receiveMore = function() {
							return handlePacket(info, '');
						};
					} else
						return handlePacket(info, '');
				}
				return;
			} else {
				const nline = line.slice(0,lpos).join('');
				lines.push(nline);
				lpos = 0;
			}
		}
		else if( l !== "\r" )
			line[lpos++] = l;
	}
}

function mimeForPath(path)
{
    let mimetype = 'text/plain';
    if( path.endsWith('.png') )
        mimetype = 'image/png';
    else if( path.endsWith('.jpg') || path.endsWith('.jpeg') )
        mimetype = 'image/jpg';
    else if( path.endsWith('.gif') )
        mimetype = 'image/gif';
    else if( path.endsWith('.webp') )
        mimetype = 'image/webp';
    else if( path.endsWith('.mp4') )
        mimetype = 'video/mp4';
    else if( path.endsWith('.webm') )
        mimetype = 'video/webm';
    else if( path.endsWith('.css') )
        mimetype = 'text/css';
    else if( path.endsWith('.js') )
        mimetype = 'text/javascript';
    else if( path.endsWith('.otf') )
        mimetype = 'font/otf';
    else if( path.endsWith('.html') )
        mimetype = 'text/html';
    return mimetype;
}

function getHTTPDate( indate )
{
	// Locale-independent, used for Date-type HTTP headers.
	const dow = [ 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat' ];
	const months = [ 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' ];

	const l_dow = dow[ indate.getUTCDay() ];
	let l_dom = indate.getUTCDate();
	if( l_dom < 10 )
		l_dom = '0'+l_dom;
	const l_mon = months[ indate.getUTCMonth() ];
	const l_year = indate.getUTCFullYear();
	let l_hour = indate.getUTCHours();
	if( l_hour < 10 )
		l_hour = '0'+l_hour;
	let l_mins = indate.getUTCMinutes();
	if( l_mins < 10 )
		l_mins = '0'+l_mins;
	let l_seconds = indate.getUTCSeconds();
	if( l_seconds < 10 )
		l_seconds = '0'+l_seconds;

	const res = l_dow+', '+l_dom+' '+l_mon+' '+l_year+' '+l_hour+':'+l_mins+':'+l_seconds+' GMT';
	return res;
}

function sendResource(info, root, path)
{
	const fullpath = root + '/' + path;
	const [sobj, serr] = os.stat(fullpath);
	if( !sobj )
	{
		console.log(`404: ${fullpath}`);
		return send404(info);
	}

	if( sobj.mode & os.S_IFDIR )
	{
		const idxPath = fullpath + '/index.html';
		const [iobj, ierr] = os.stat(idxPath);
		if( iobj && iobj.mode & os.S_IFREG )
		{
			let mimetype = mimeForPath(idxPath);
			return sendFile(info, idxPath, mimetype);
		}

		const content = dirListing(root, path);
		return sendContent(info, content, 'text/html');
	}
	else if( sobj.mode & os.S_IFREG )
	{
		//sendContent(info, "I'm a file.", 'text/html');
		let mimetype = mimeForPath(path);
		sendFile(info, fullpath, mimetype);
	}
	else
		sendContent(info, "I'm something else.", 'text/html');
}

function dirListing(root, path)
{
	const start = new Date();

	const fullpath = `${root}/${path}`;
	const [ents, rerr] = os.readdir(fullpath);

	let result = `<!DOCTYPE html>
<html>
	<head>
		<title>Listing of ${path}</title>
		<link rel="stylesheet" href="/internal/css/style.css"></link>
		<script src="/internal/js/gallery.js" defer="true"></script>
	</head>
	<body onLoad="initGallery();">
		<div id="background"></div>
		<div id="content">
			<h1>Listing of ${path}</h1>
			<hr />
			<table width="100%">`;

	let images = [];
	let index = 0;

	let pathParts = path.split(/\//g).filter( function(p) { return p.length > 0; } );
	if( pathParts.length > 0 )
	{
		pathParts.pop();
		const prevPath = pathParts.join('/');
		result += `<tr>
			<td colspan="4"><a href="/${prevPath}">Up to /${prevPath}</a></td>
		</tr>`;
	}

	const lc = path.substr( path.length-1, 1 );
	if( lc !== '/' )
		path = path + '/';

	for( const e of ents )
	{
		if( e === '.' || e === '..' )
			continue;

		const filepath = `${fullpath}/${e}`;
		const [sobj, serr] = os.stat(filepath);
		let niceSize = '???';
		let mdate = '???';
		if( !sobj )
			niceSize = serr;
		else
		{
			niceSize = bytesToSize(sobj.size);
			mdate = new Date(sobj.mtime);
		}

		let imgLink = '';
                if( e.endsWith('.png') || e.endsWith('.jpg') || e.endsWith('.webp') || e.endsWith('.jpeg') || e.endsWith('.gif') )
		{
			images.push( { 'path':`${path}${e}`, 'name':e } );
			imgLink = `<span onClick="openGallery(${index});" style="cursor: pointer;"><span class="galleryIcon"></span></span>`;
			index++;
		}

		result += `<tr>
			<td><a href="${path}${e}">${e}</a></td>
			<td>${niceSize}</td>
			<td>${mdate}</td>
			<td>${imgLink}</td>
		</tr>`;
	}

	result += `</table></div>
	<script>const images = ${JSON.stringify(images)};</script>
	<div id="imageViewer" onClick="closeGallery();">
		<img onClick="closeGallery();" id="focusImage" />
	</div>
	<div id="imageLabel">Norq</div>
	<div id="loader"><div class="lds-ring"><div></div><div></div><div></div><div></div></div></div>
	</body></html>`;

	const duration = (new Date().getTime()) - start.getTime();
	console.log(`dirListing took ${duration}ms`);

	return result;
}

// Regular:
function runServer(sinfo)
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
		const start = new Date();

		let info;
		try {
			info = net.accept(serverfd);
			console.log(`Connection from ${info.family}:[${info.ip}]:${info.port}`);
		} catch(err) {
			console.log("accept: "+err);
		}

		try {
			info.write = function(data, br)
			{
				if( !br )
					br = data.byteLength;

				try {
					return os.write(this.fd, data, 0, br);
				} catch(err) {
					console.log("write error: "+err);
				}
			};
			info.flush = function()
			{
				console.log("Sync.");
				//net.sync(info.fd);
			};
			info.close = function()
			{
				console.log("Closing connection...");
				os.setReadHandler(info.fd, null);
				net.shutdown(info.fd);
				os.close(this.fd);
				console.log("Closed.");
				info.open = false;
				//console.log( new Error().stack );
			};
			info.readHandler = function(data, br)
			{
				try {
					const asstr = uint8arrayToString(data);
					handlePacket(info, asstr, data, br);
				} catch(err) {
					console.log("readHandler error: "+err);
					console.log( new Error().stack );
				}
			};
			setupClient(info);
		} catch(ierr) {
			console.log("setup: "+ierr);
			os.setReadHandler(info.fd, null);
			os.close(info.fd);
		}

		console.log("Accept took "+( (new Date().getTime()) - start.getTime() )+"ms");
	});

	console.log(`Listening on ${sinfo.family}:[${sinfo.ip}]:${sinfo.port}`);
	return serverfd;
}

function setupClient(info)
{
	console.log("info: "+JSON.stringify(info,null,2));
	info.open = true;

	let handleRead = function() {
		let data = new Uint8Array(8192);
		try {
			const br = os.read(info.fd, data.buffer, 0, data.length);
			if( br < 0 ) {
				console.log("read error");
				os.setReadHandler(info.fd, null);
				return;
			}
			else if( 0 == br )
			{
				console.log(`Connection closed from ${info.family}:[${info.ip}]:${info.port}`);
				info.close();
			}
			else
			{
				info.readHandler(data, br);
				if( info.open && info.transmitting )
				{
					os.setReadHandler(info.fd, null);
					let orm = info.receiveMore;
					info.receiveMore = function() {
						console.log("Reenabling read handler...");
						os.setReadHandler(info.fd, handleRead);
						if( orm )
							orm();
						delete info.receiveMore;
					};
				}
			}
		} catch(err) {
			console.log("readhandler: "+err);
			os.setReadHandler(info.fd, null);
		}
	};

	os.setReadHandler(info.fd, handleRead);
}

// TLS:
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

				let rval = false;
				try {
					rval = this.tlsSocket.write(data);
				} catch(err) {
					console.log("tlsSocket.write error: "+err);
					this.close();
				}
				return rval;
			};
			info.flush = function()
			{
				console.log("Sync.");
				//net.sync(info.fd);
			};
			info.close = function()
			{
				console.log("Closing connection...");
				os.setReadHandler(info.fd, null);
				net.shutdown(info.fd);
				os.close(this.fd);
				console.log("Closed.");
				//console.log( new Error().stack );
			};
			info.readHandler = function(data)
			{
				const asstr = uint8arrayToString(data);
				handlePacket(info, asstr);
			};
			setupTLSClient(info);
		} catch(ierr) {
			console.log("setup: "+ierr);
			os.setReadHandler(info.fd, null);
			os.close(info.fd);
		}
	});

	try {
		sinfo.tls = wolfssl.tlsServer(sinfo.cert, sinfo.key);
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

		try {
			const br = info.tlsSocket.read(4096);
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
				return info.readHandler( new Uint8Array(br) );
		} catch(err) {
			console.log("readhandler: "+err);
			os.setReadHandler(info.fd, null);
		}
	});
}
//runTests();

const sinfo = { 'family':'inet6', 'ip':'::', 'port':8082, 'secure':true, 'cert':'certs/testing.crt', 'key':'certs/testing.key' };
runTLSServer(sinfo);
const sinfo2 = { 'family':'inet6', 'ip':'::', 'port':8081 };
runServer(sinfo2);
/*
std.gc();

std.exit(0);
*/
