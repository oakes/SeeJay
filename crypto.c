#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "crypto.h"
#include "util.h"

/*
 * Generates an RSA-2048 private key.
 */

int create_private_key(void **priv_key_ptr) {
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

	EVP_PKEY *priv_key = EVP_PKEY_new();
	if (EVP_PKEY_assign_RSA(priv_key, rsa) == 0) {
		printf("Failed to parse the private key\n");
		return 0;
	}

	*priv_key_ptr = priv_key;

	return 1;
}

/*
 * Creates a public certificate from the supplied private key.
 */

int create_public_key(void **pub_key_ptr, void *priv_key)
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

	*pub_key_ptr = x509;

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

int read_private_key(void **priv_key_ptr, char *name)
{
	EVP_PKEY *priv_key;
	FILE *file;

	if ((file = fopen(name, "r")) == NULL ||
		(priv_key = PEM_read_PrivateKey(file, NULL, NULL, NULL)) == NULL)
	{
		printf("Failed to read the private key\n");
		fclose(file);
		return 0;
	}
	fclose(file);

	*priv_key_ptr = priv_key;

	return 1;
}

/*
 * Reads the public key from the disk.
 */

int read_public_key(void **pub_key_ptr, char *name)
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

	*pub_key_ptr = x509;

	return 1;
}

/*
 * Generates a hash of the public key.
 */

int create_fingerprint(unsigned char *hash_ptr, void *pub_key)
{
	OpenSSL_add_all_digests();
	const EVP_MD *digest = EVP_get_digestbyname("sha1");
	unsigned int n;
	X509_digest(pub_key, digest, hash_ptr, &n);
	return 1;
}

/*
 * Determines if we trust the certificate we've received.
 */

static int tls_verify_callback(int ok, X509_STORE_CTX *ctx) {
	X509 *x509 = X509_STORE_CTX_get_current_cert(ctx);
	SSL *ssl = X509_STORE_CTX_get_ex_data
		(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

	/* if we're the client, make sure their public key matches the hash */
	unsigned char *hash = SSL_get_ex_data(ssl, 0);
	if (hash != NULL) {
		unsigned char expected_hash[HASH_SIZE];
		create_fingerprint(expected_hash, x509);
		if (memcmp(hash, expected_hash, HASH_SIZE)) {
			printf("public key doesn't match fingerprint\n");
			return 0;
		}
	}

	return 1;
}

/*
 * Initializes the TLS context.
 */

int tls_global_init(void **ctx_ptr, void *priv_key, void *pub_key)
{
	/* create the context */
	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX *ctx = SSL_CTX_new(TLSv1_method());

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
		tls_verify_callback
	);

	*ctx_ptr = ctx;

	return 1;
}

/*
 * Initializes a TLS object for a specific connection.
 */

int tls_local_init(void **ssl_ptr, void *ctx, unsigned char *hash)
{
	SSL *ssl = SSL_new(ctx);
	SSL_set_ex_data(ssl, 0, hash);
	*ssl_ptr = ssl;
	return 1;
}
