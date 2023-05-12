# quickjs-hash
Simple base64 encoding and md5/sha256 hashing module for QuickJS using WolfSSL

Building requires editing the Makefile and pointing it to your quickjs-2017-03-27 directory, and having OpenSSL 3.x (and headers) installed and findable via pkg-config.

See **example.js** for usage.

Consists of only 4 methods:
 * toBase64
 * fromBase64
 * md5sum
 * sha256sum

Each method accepts one parameter.

*toBase64*, *md5sum*, and *sha256sum* expect a Uint8Array as the only parameter.

*toBase64* returns a string containing the Base64 encoded data.

*md5sum* and *sha256sum* return a hex-encoded string representing the calculated hash of the contents passed.

*fromBase64* expects a string as the only parameter and returns a Uint8Array (actually, a Uint32Array but whatever.)

Feature requests and PRs are welcome. Also check out my [low-level sockets module](https://github.com/danieloneill/quickjs-net) or my [OpenSSL-based hash module](https://github.com/danieloneill/quickjs-hash).

