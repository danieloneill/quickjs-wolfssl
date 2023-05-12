import * as hash from "quickjs-wolfssl.so";
import * as std from "std";

function runTests()
{
	const testString = 'Well I met an old man dying on a train. No more destination, no more pain. Well he said one thing: "Before I graduate never let your fear decide your fate"';
	
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
	
	const data = stringToUint8array(testString);
	console.log(`Original: ${testString}`);

	const asB64 = hash.toBase64(data.buffer);
	console.log(`Base64 => ${asB64}`);
	
	const fromB64 = hash.fromBase64(asB64);
	console.log(`Base64 <= ${uint8arrayToString(fromB64)}`);

	const md5sum = hash.md5sum(data.buffer);
	console.log(`MD5 should be bdc20bf28ed988c221cb6cfa2b417b08, got ${md5sum}`);
	
	const sha256sum = hash.sha256sum(data.buffer);
	console.log(`SHA256 should be 4a4c36949311dfbe0cae22f498e0e4d7b714a38392681e8aff5620721aa6d98e, got ${sha256sum}`);
}

runTests();

std.gc();

std.exit(0);
