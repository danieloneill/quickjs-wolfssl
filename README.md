# quickjs-hash
Simple base64 encoding and md5/sha256 hashing module for QuickJS using WolfSSL

Building requires editing the Makefile and pointing it to your quickjs-2017-03-27 directory, and having OpenSSL 3.x (and headers) installed and findable via pkg-config.

WolfSSL doesn't build with Base64 encoding support on ARM by default, so in my case (aarch64) I had to build WolfSSL with it explicitly enabled.

See **example.js** for usage.

Consists of only a few methods:
- toBase64
- fromBase64
- md5sum
- sha256sum
- uint8ArrayToString
- stringToUint8Array
- tlsServer - which provides
  - wrap(fd) - which provides:
    - read
    - write
    - accept
    - shutdown

Each method accepts one parameter.

*toBase64*, *md5sum*, and *sha256sum* expect a Uint8Array as the only parameter.

*toBase64* returns a string containing the Base64 encoded data.

*md5sum* and *sha256sum* return a hex-encoded string representing the calculated hash of the contents passed.

*fromBase64* expects a string as the only parameter and returns a Uint8Array (actually, a Uint32Array but whatever.)

*uint8ArrayToString* accepts a UInt8Array and returns it as a string. *stringToUint8Array* does the opposite. They both only accept one arg, and you can probably guess what arg it is.

*tlsServer* expects a path to your certificate and a path to your private key, and returns a new TLS server object which just has the 'wrap' method.

*wrap* accepts a file descriptor and returns a super-saiyan version of it as a TLS client sorta. I say 'sorta' because the new object only has 4 methods, since you can use standard os.* and net.* methods on the original socket as usual for other purposes, but you will need new read, wrote, accept, and shutdown methods when working with TLS.

*read(maxlen)* returns a UInt8Array of received bytes or throws on error.

*write(data)* writes the provided UInt8Array to the client, or throws on error. Returns true too, for some reason.

*accept* only makes sense on a new client (that was just wrapped) and needs to be called to do the post-vanilla-accept handshaking and negociations.

*shutdown* shuts down the socket.

Feature requests and PRs are welcome. Also check out my [low-level sockets module](https://github.com/danieloneill/quickjs-net) or my [OpenSSL-based hash module](https://github.com/danieloneill/quickjs-hash).

--

To use the httpserver.js example, your files go into webroot/ and you also need to copy/link the net.so result from the low-level sockets module above to the same dir as the script. It doesn't do much, but it does offer dir listings.

I shouldn't have to say this, but httpserver.js isn't intended for any production purposes: it's just a toy I threw in for testing.
