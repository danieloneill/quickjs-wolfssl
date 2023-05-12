#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "quickjs-wolfssl.h"
#include "cutils.h"

#define HASH_CHUNKSIZE 512

unsigned char *toBase64(const unsigned char *strIn, size_t lenIn)
{
	if( 0 == lenIn )
		lenIn = strlen((char*)strIn);

	uint32_t outLen = lenIn * 2 + 1;
	unsigned char *encoded = malloc( outLen );

	if( Base64_Encode_NoNl(strIn, lenIn, encoded, &outLen) != 0 )
	{
		// error encoding input buffer
		free(encoded);
		return NULL;
	}

	return encoded;
}

size_t fromBase64(const unsigned char *strIn, size_t lenIn, unsigned char **out)
{
	unsigned int outLen = (lenIn * 3 + 3) / 4;
	unsigned char *decoded = malloc(outLen);
	if( Base64_Decode(strIn, lenIn, decoded, &outLen) != 0 ) {
		// error decoding input buffer
		return -1;
	}

	*out = decoded;
	return outLen;
}

static JSValue js_hash_tobase64(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv)
{
	size_t inlen;
	unsigned char *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to encode");
		return JS_UNDEFINED;
	}

	unsigned char *ptr = toBase64(instr, inlen);
	if( !ptr )
	{
		JS_ThrowTypeError(ctx, "wolfssl error");
		return JS_UNDEFINED;
	}

	JSValue js_b64 = JS_NewString(ctx, ptr);
	free(ptr);

	return js_b64;
}

static JSValue js_hash_frombase64(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
	size_t inlen;
	int outlen;
	uint8_t *ptr;
	const char *instr = JS_ToCStringLen(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to decode");
		return JS_UNDEFINED;
	}

	outlen = fromBase64(instr, inlen, &ptr);
	JS_FreeCString(ctx, instr);
	if( -1 == outlen )
	{
		JS_ThrowTypeError(ctx, "wolfssl error");
		return JS_UNDEFINED;
	}

	JSValue arr = JS_NewArray(ctx);
	for( int x=0; x < outlen; x++ )
	{
		JSValue val = JS_NewInt32(ctx, ptr[x]);
		JS_SetPropertyUint32(ctx, arr, x, val);
	}
	free(ptr);

	return arr;
}

static JSValue js_digest( JSContext *ctx, JSValueConst this_val,
		        int argc, JSValueConst *argv,
				int (*digest)(const unsigned char *, unsigned int len, unsigned char *hash),
				size_t digestLen
) {
	size_t inlen;
	uint8_t *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to digest");
		return JS_UNDEFINED;
	}

	unsigned char *res = malloc(digestLen);
	int rv = digest(instr, inlen, res);
	if( 0 != rv )
	{
		free(res);
		JS_ThrowTypeError(ctx, "require input to digest");
		return JS_UNDEFINED;
	}

	char asHex[ digestLen * 2 + 1 ];
	memset(asHex, 0, sizeof(asHex));

	int cursor = 0;
	for(int i = 0; i < digestLen; i++)
		cursor += sprintf(&asHex[cursor], "%02x", res[i]);
	free(res);

	JSValue hexDigest = JS_NewString(ctx, asHex);
	return hexDigest;
}

static JSValue js_hash_md5sum(JSContext *ctx, JSValueConst this_val,
                             int argc, JSValueConst *argv)
{
	return js_digest( ctx, this_val, argc, argv, wc_Md5Hash, 16 ); // 128bit
}

static JSValue js_hash_sha256sum(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
	return js_digest( ctx, this_val, argc, argv, wc_Sha256Hash, 32 ); // 256bit
}

static const JSCFunctionListEntry js_hash_funcs[] = {
    JS_CFUNC_DEF("toBase64", 1, js_hash_tobase64 ),
    JS_CFUNC_DEF("fromBase64", 1, js_hash_frombase64 ),
    JS_CFUNC_DEF("md5sum", 1, js_hash_md5sum ),
    JS_CFUNC_DEF("sha256sum", 1, js_hash_sha256sum ),
};

static int js_hash_init(JSContext *ctx, JSModuleDef *m)
{
    JS_SetModuleExportList(ctx, m, js_hash_funcs,
                           countof(js_hash_funcs));
    return 0;
}

JSModuleDef *js_init_module(JSContext *ctx, const char *module_name)
{
    JSModuleDef *m = JS_NewCModule(ctx, module_name, js_hash_init);
    if (!m)
        return NULL;

    JS_AddModuleExportList(ctx, m, js_hash_funcs, countof(js_hash_funcs));
    return m;
}

