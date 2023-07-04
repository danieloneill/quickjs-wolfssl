#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hash.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>

#include "quickjs-wolfssl.h"
#include "cutils.h"

#define HASH_CHUNKSIZE 512

static JSClassID tlsServerClassID;
static JSClassID tlsSocketClassID;
typedef struct TLSServerContext {
	WOLFSSL_CTX		*ctx;
} TLSServerContext;
typedef struct TLSSocketContext {
	TLSServerContext	*sctx;
	WOLFSSL				*ssl;
	int					fd;
} TLSSocketContext;

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
		return JS_EXCEPTION;
	}

	unsigned char *ptr = toBase64(instr, inlen);
	if( !ptr )
	{
		JS_ThrowTypeError(ctx, "wolfssl error");
		return JS_EXCEPTION;
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
		return JS_EXCEPTION;
	}

	outlen = fromBase64(instr, inlen, &ptr);
	JS_FreeCString(ctx, instr);
	if( -1 == outlen )
	{
		JS_ThrowTypeError(ctx, "wolfssl error");
		return JS_EXCEPTION;
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
			enum wc_HashType hashType,
				size_t digestLen
) {
	size_t inlen;
	uint8_t *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to digest");
		return JS_EXCEPTION;
	}

	unsigned char *res = malloc(digestLen);
        int rv = wc_Hash(hashType, instr, inlen, res, digestLen);
	if( 0 != rv )
	{
		free(res);
		JS_ThrowTypeError(ctx, "digest failed");
		return JS_EXCEPTION;
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
	return js_digest( ctx, this_val, argc, argv, WC_HASH_TYPE_MD5, 16 ); // 128bit
}

static JSValue js_hash_sha256sum(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
	return js_digest( ctx, this_val, argc, argv, WC_HASH_TYPE_SHA256, 32 ); // 256bit
}

static JSValue js_hash_tls_socket_read(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
	if( argc < 1 )
	{
		JS_ThrowTypeError(ctx, "requires a parameter");
		return JS_EXCEPTION;
	}

	int32_t num;
	if( JS_ToInt32(ctx, &num, argv[0]) )
	{
		JS_ThrowTypeError(ctx, "requires a max length parameter");
		return JS_EXCEPTION;
	}

	char *buff = malloc(num);
	if( !buff )
	{
		JS_ThrowTypeError(ctx, "buffer allocation failure");
		return JS_EXCEPTION;
	}

	TLSSocketContext *tctx = JS_GetOpaque2(ctx, this_val, tlsSocketClassID);
	int ret = wolfSSL_read(tctx->ssl, buff, num);
	if( ret == -1 )
	{
		free(buff);
		JS_ThrowTypeError(ctx, "wolfSSL_read error");
		return JS_EXCEPTION;
	}

	JSValue arr = JS_NewArray(ctx);
	for( int x=0; x < ret; x++ )
	{
		JSValue val = JS_NewInt32(ctx, buff[x]);
		JS_SetPropertyUint32(ctx, arr, x, val);
	}
	free(buff);

	return arr;
}

static JSValue js_hash_tls_socket_write(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
	if( argc < 1 )
	{
		JS_ThrowTypeError(ctx, "requires a parameter");
		return JS_EXCEPTION;
	}

	size_t inlen;
	unsigned char *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to write");
		return JS_EXCEPTION;
	}

	TLSSocketContext *tctx = JS_GetOpaque2(ctx, this_val, tlsSocketClassID);
	int ret = wolfSSL_write(tctx->ssl, instr, inlen);
	if( ret != inlen )
	{
		JS_ThrowTypeError(ctx, "wolfSSL_write error");
		return JS_EXCEPTION;
	}

	return JS_TRUE;
}

static JSValue js_hash_tls_socket_accept(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
	TLSSocketContext *tctx = JS_GetOpaque2(ctx, this_val, tlsSocketClassID);

	int ret = wolfSSL_accept(tctx->ssl);
	if( ret != WOLFSSL_SUCCESS )
	{
		char errStr[80];
		int errnum = wolfSSL_get_error(tctx->ssl, ret);
		wolfSSL_ERR_error_string(errnum, errStr);
		JS_ThrowTypeError(ctx, "wolfSSL_accept error = %d: %s", errnum, errStr);
		return JS_EXCEPTION;
	}

	return JS_TRUE;
}

static JSValue js_hash_tls_socket_shutdown(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
	TLSSocketContext *tctx = JS_GetOpaque2(ctx, this_val, tlsSocketClassID);
	int ret = wolfSSL_shutdown(tctx->ssl);
	if( ret != WOLFSSL_SUCCESS )
	{
		JS_ThrowTypeError(ctx, "wolfSSL_shutdown error = %d", wolfSSL_get_error(tctx->ssl, ret));
		return JS_EXCEPTION;
	}

	return JS_TRUE;
}

static void js_destroy_tls_socket(JSRuntime *rt, JSValue obj)
{
	TLSSocketContext *nctx = JS_GetOpaque(obj, tlsSocketClassID);
	wolfSSL_free(nctx->ssl);
	free(nctx);
}

static const JSCFunctionListEntry js_hash_tls_socket_proto_funcs[] = {
    JS_CFUNC_DEF("read", 1, js_hash_tls_socket_read ),
    JS_CFUNC_DEF("write", 1, js_hash_tls_socket_write ),
    JS_CFUNC_DEF("accept", 0, js_hash_tls_socket_accept ),
    JS_CFUNC_DEF("shutdown", 0, js_hash_tls_socket_shutdown ),
};

static JSValue js_hash_tls_wrap(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
	if( argc < 1 )
	{
		JS_ThrowTypeError(ctx, "requires a file descriptor");
		return JS_EXCEPTION;
	}

	int32_t num;
	if( JS_ToInt32(ctx, &num, argv[0]) )
	{
		JS_ThrowTypeError(ctx, "requires a file descriptor");
		return JS_EXCEPTION;
	}

	TLSServerContext *tctx = JS_GetOpaque2(ctx, this_val, tlsServerClassID);

	TLSSocketContext *sctx = malloc(sizeof(TLSSocketContext));
	sctx->fd = num;
	sctx->sctx = tctx;
	sctx->ssl = wolfSSL_new(tctx->ctx);
	wolfSSL_set_fd(sctx->ssl, num);

	JSValue nval = JS_NewObjectClass(ctx, tlsSocketClassID);
	JS_SetOpaque(nval, sctx);

	printf("Wrap got FD#:%d\n", num);
	return nval;
}

static const JSCFunctionListEntry js_hash_tls_proto_funcs[] = {
    JS_CFUNC_DEF("wrap", 1, js_hash_tls_wrap ),
};

static JSValue js_new_tls_server(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
	if( argc < 2 )
	{
		JS_ThrowTypeError(ctx, "requires path to certificate and key files");
		return JS_EXCEPTION;
	}

	size_t fileCertLen;
	const char *fileCert = JS_ToCStringLen(ctx, &fileCertLen, argv[0]);
	if( !fileCert )
	{
		JS_ThrowTypeError(ctx, "requires path to a certificate file");
		return JS_EXCEPTION;
	}

	size_t fileKeyLen;
	const char *fileKey = JS_ToCStringLen(ctx, &fileKeyLen, argv[1]);
	if( !fileKeyLen )
	{
		JS_ThrowTypeError(ctx, "requires path to a private key file");
		return JS_EXCEPTION;
	}

	TLSServerContext *tctx = malloc(sizeof(TLSServerContext));

	/* Create and initialize WOLFSSL_CTX */
    if ((tctx->ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
		free(tctx);
		JS_ThrowTypeError(ctx, "ERROR: failed to create WOLFSSL_CTX");
		return JS_EXCEPTION;
    }

    wolfSSL_CTX_set_verify(tctx->ctx, WOLFSSL_VERIFY_NONE, NULL);

    /* Load server certificates into WOLFSSL_CTX */
    if( wolfSSL_CTX_use_certificate_file(tctx->ctx, fileCert, SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS )
	{
		free(tctx);
		JS_ThrowTypeError(ctx, "ERROR: failed to load certificate, please check the file.");
		return JS_EXCEPTION;
    }

    /* Load server key into WOLFSSL_CTX */
    if( wolfSSL_CTX_use_PrivateKey_file(tctx->ctx, fileKey, SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS )
	{
		free(tctx);
		JS_ThrowTypeError(ctx, "ERROR: failed to key file, please check the file");
		return JS_EXCEPTION;
    }

	JSValue nval = JS_NewObjectClass(ctx, tlsServerClassID);
	JS_SetOpaque(nval, tctx);
	return nval;
}

static void js_destroy_tls_server(JSRuntime *rt, JSValue val)
{
	TLSServerContext *nctx = JS_GetOpaque(val, tlsServerClassID);
	wolfSSL_CTX_free(nctx->ctx);
	free(nctx);
}

static JSValue js_hash_uint8array_to_string(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv)
{
	if( argc < 1 )
	{
		JS_ThrowTypeError(ctx, "requires uint8array to convert as input");
		return JS_EXCEPTION;
	}

	size_t inlen;
	unsigned char *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to convert");
		return JS_EXCEPTION;
	}

	JSValue newstr = JS_NewStringLen(ctx, instr, inlen);
	return newstr;
}

static JSValue js_hash_string_to_uint8array(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
	if( argc < 1 )
	{
		JS_ThrowTypeError(ctx, "requires string to convert as input");
		return JS_EXCEPTION;
	}

	size_t strLen;
	const char *str = JS_ToCStringLen(ctx, &strLen, argv[0]);
	if( !str )
	{
		JS_ThrowTypeError(ctx, "requires a valid string to convert");
		return JS_EXCEPTION;
	}

	JSValue arr = JS_NewArray(ctx);
	for( int x=0; x < strLen; x++ )
	{
		JSValue val = JS_NewInt32(ctx, str[x]);
		JS_SetPropertyUint32(ctx, arr, x, val);
	}

	return arr;
}

static const JSCFunctionListEntry js_hash_funcs[] = {
    JS_CFUNC_DEF("toBase64", 1, js_hash_tobase64 ),
    JS_CFUNC_DEF("fromBase64", 1, js_hash_frombase64 ),
    JS_CFUNC_DEF("md5sum", 1, js_hash_md5sum ),
    JS_CFUNC_DEF("sha256sum", 1, js_hash_sha256sum ),

    JS_CFUNC_DEF("uint8ArrayToString", 1, js_hash_uint8array_to_string ),
    JS_CFUNC_DEF("stringToUint8Array", 1, js_hash_string_to_uint8array ),

    JS_CFUNC_DEF("tlsServer", 2, js_new_tls_server ),
};

static int js_hash_init(JSContext *ctx, JSModuleDef *m)
{
    JS_SetModuleExportList(ctx, m, js_hash_funcs,
                           countof(js_hash_funcs));

	tlsServerClassID = 0;
	JS_NewClassID(&tlsServerClassID);

	JSClassDef tlsServerClassDef = { .class_name = "TLSServerContext", .finalizer = js_destroy_tls_server, .gc_mark = NULL, .call = NULL, .exotic = NULL };
	JS_NewClass(JS_GetRuntime(ctx), tlsServerClassID, &tlsServerClassDef);

	// Server:
	JSValue tlsServerProto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, tlsServerProto, js_hash_tls_proto_funcs,
                               countof(js_hash_tls_proto_funcs));
    JS_SetClassProto(ctx, tlsServerClassID, tlsServerProto);

	// Socket:
	tlsSocketClassID = 0;
	JS_NewClassID(&tlsSocketClassID);

	JSClassDef tlsSocketClassDef = { .class_name = "TLSSocketContext", .finalizer = js_destroy_tls_socket, .gc_mark = NULL, .call = NULL, .exotic = NULL };
	JS_NewClass(JS_GetRuntime(ctx), tlsSocketClassID, &tlsSocketClassDef);

	JSValue tlsSocketProto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, tlsSocketProto, js_hash_tls_socket_proto_funcs,
                               countof(js_hash_tls_socket_proto_funcs));
    JS_SetClassProto(ctx, tlsSocketClassID, tlsSocketProto);

    return 0;
}

JSModuleDef *js_init_module(JSContext *ctx, const char *module_name)
{
	signal(SIGPIPE, SIG_IGN);

	wolfSSL_Init();

    JSModuleDef *m = JS_NewCModule(ctx, module_name, js_hash_init);
    if (!m)
        return NULL;

    JS_AddModuleExportList(ctx, m, js_hash_funcs, countof(js_hash_funcs));
    return m;
}

