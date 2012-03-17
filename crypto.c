#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* necessary for dtls_verify_cookie and dtls_create_cookie */
#include <event2/event.h>
#include <netinet/in.h>

#include "crypto.h"
#include "util.h"

#define COOKIE_SECRET_LENGTH 16

/*
 * Generates an RSA-2048 private key.
 */

int create_private_key(void **priv_key) {
	RSA *rsa;
	BIGNUM num;
	bzero(&num, sizeof(num));

	if (BN_set_word(&num, 65537) == 0 ||
		(rsa = RSA_new()) == NULL ||
		RSA_generate_key_ex(rsa, 2048, &num, NULL) == 0)
	{
		printf("Failed to generate private key\n");
		return 0;
	}

	EVP_PKEY *pkey = EVP_PKEY_new();
	if (EVP_PKEY_assign_RSA(pkey, rsa) == 0) {
		printf("Failed to parse the private key\n");
		return 0;
	}

	*priv_key = pkey;

	return 1;
}

/*
 * Creates a public certificate from the supplied private key.
 */

int create_public_key(void **pub_key, void *priv_key)
{
	/* create X509 request */
	X509_REQ *req = NULL;
	if ((req = X509_REQ_new()) == NULL ||
		X509_REQ_set_version(req, 0) == 0 ||
		X509_REQ_set_pubkey(req, priv_key) == 0)
	{
		printf("Failed to create X509 request\n");
		return 0;
	}

	/* create X509 cert */
	X509 *x509 = NULL;
	BIGNUM num;
	bzero(&num, sizeof(num));
	EVP_PKEY *tempkey = NULL;
	if ((x509 = X509_new()) == NULL ||
		BN_pseudo_rand(&num, 64, 0, 0) == 0 ||
		BN_to_ASN1_INTEGER(&num, X509_get_serialNumber(x509)) == 0 ||
		X509_gmtime_adj(X509_get_notBefore(x509), 0) == 0 ||
		X509_gmtime_adj(X509_get_notAfter(x509), 365*10) == 0 ||
		(tempkey = X509_REQ_get_pubkey(req)) == NULL ||
		(X509_set_pubkey(x509, tempkey)) == 0 ||
		X509_sign(x509, priv_key, EVP_sha256()) == 0)
	{
		printf("Failed to create X509 certificate\n");
		return 0;
	}

	/* free various allocations */
	EVP_PKEY_free(tempkey);
	X509_REQ_free(req);

	*pub_key = x509;

	return 1;
}

/*
 * Writes the private key to the disk.
 */

int write_private_key(void *priv_key, char *name)
{
	BIO *out = BIO_new(BIO_s_file());
	const EVP_CIPHER *enc = NULL; /* EVP_aes_256_cbc(); */
	if (BIO_write_filename(out, name) <= 0 ||
		PEM_write_bio_PrivateKey(out, priv_key, enc, NULL, 0, NULL, NULL) == 0)
	{
		printf("Failed to write private key\n");
		return 0;
	}
	BIO_free_all(out);

	return 1;
}

/*
 * Writes the public key to the disk.
 */

int write_public_key(void *pub_key, char *name)
{
	BIO *out = BIO_new(BIO_s_file());
	if (BIO_write_filename(out, name) <= 0 ||
		PEM_write_bio_X509(out, pub_key) == 0)
	{
		printf("failed to write public key\n");
		return 0;
	}
	BIO_free_all(out);

	return 1;
}

/*
 * Reads the private key from the disk.
 */

int read_private_key(void **priv_key, char *name)
{
	EVP_PKEY *pkey;
	FILE *file;

	if ((file = fopen(name, "r")) == NULL ||
		(pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL)) == NULL)
	{
		printf("Failed to read the private key\n");
		fclose(file);
		return 0;
	}
	fclose(file);

	*priv_key = pkey;

	return 1;
}

/*
 * Reads the public key from the disk.
 */

int read_public_key(void **pub_key, char *name)
{
	X509 *x509;
	FILE *file;

	if ((file = fopen(name, "r")) == NULL ||
		(x509 = PEM_read_X509(file, NULL, NULL, NULL)) == NULL)
	{
		printf("Failed to read the public key\n");
		fclose(file);
		return 0;
	}
	fclose(file);

	*pub_key = x509;

	return 1;
}

/*
 * Determines if we trust the certificate we've received.
 */

static int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	return 1;
}

/*
 * Creates the cookie necessary for the DTLS handshake.
 */

static int dtls_create_cookie
	(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
	int cookie_initialized = 0;
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* initialize a random secret */
	if (!cookie_initialized) {
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
			printf("Error setting random cookie secret\n");
			return 0;
		}
		cookie_initialized = 1;
	}

	/* read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL) {
		printf("Out of memory\n");
		return 0;
	}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

/*
 * Verifies the cookie necessary for the DTLS handshake.
 */

static int dtls_verify_cookie
	(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
	int cookie_initialized = 0;
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* if secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized) {
		return 0;
	}

	/* cead peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL) {
		printf("Out of memory\n");
		return 0;
	}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
}

/*
 * Initializes the DTLS server.
 */

int dtls_server_init(void **ctx_ptr, void *priv_key, void *pub_key)
{
	/* initialize the context */
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	SSL_CTX *ctx = SSL_CTX_new(DTLSv1_server_method());
	SSL_CTX_set_cipher_list(ctx, "AES256-SHA");
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	/* load the files */
	if (!SSL_CTX_use_certificate(ctx, pub_key)) {
		printf("Failed to load public key\n");
		return 0;
	}
	if (!SSL_CTX_use_PrivateKey(ctx, priv_key)) {
		printf("Failed to load private key\n");
		return 0;
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Invalid private key\n");
		return 0;
	}

	/* client must authenticate */
	SSL_CTX_set_verify(
		ctx,
		SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
		dtls_verify_callback
	);
	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, dtls_create_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, dtls_verify_cookie);

	*ctx_ptr = ctx;

	return 1;
}

int dtls_server_listen(void **ssl_ptr, int sock, void *ctx)
{
	BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);
	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} client_addr;

	if (DTLSv1_listen(ssl, &client_addr) <= 0) {
		BIO_free(bio);
		SSL_free(ssl);
		return 0;
	}

	*ssl_ptr = ssl;

	return 1;
}

/*
 * Initializes the DTLS client.
 */

int dtls_client_init(void **ssl_ptr, int sock, void *ctx, void *remote_addr)
{
	struct timeval timeout;
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;

	BIO *bio = BIO_new_dgram(sock, BIO_CLOSE);
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, remote_addr);
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);

	if (SSL_connect(ssl) < 0) {
		printf("SSL_connect() failed\n");
		return 0;
	}

	*ssl_ptr = ssl;

	return 1;
}
