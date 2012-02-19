#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "crypto.h"

int create_keys(char *priv_name, char *pub_name) {
	/* create private key */

	RSA *rsa;
	BIGNUM num;
	bzero(&num, sizeof(num));
	EVP_PKEY pkey;
	bzero(&pkey, sizeof(pkey));
	if (BN_set_word(&num, 0x1001) == 0 ||
		(rsa = RSA_new()) == NULL ||
		RSA_generate_key_ex(rsa, 2048, &num, NULL) == 0 ||
		EVP_PKEY_assign_RSA(&pkey, rsa) == 0)
	{
		printf("failed to generate RSA key\n");
		return -1;
	}

	/* create X509 request */

	X509_REQ *req = NULL;
	if ((req = X509_REQ_new()) == NULL ||
		X509_REQ_set_version(req, 0) == 0 ||
		X509_REQ_set_pubkey(req, &pkey) == 0)
	{
		printf("failed to create X509 request\n");
		return -1;
	}

	/* create X509 cert */

	X509 *x509 = NULL;
	bzero(&num, sizeof(num));
	EVP_PKEY *tempkey = NULL;
	if ((x509 = X509_new()) == NULL ||
		BN_pseudo_rand(&num, 64, 0, 0) == 0 ||
		BN_to_ASN1_INTEGER(&num, X509_get_serialNumber(x509)) == 0 ||
		//X509_set_issuer_name(x509, X509_REQ_get_subject_name(req)) ||
		X509_gmtime_adj(X509_get_notBefore(x509), 0) == 0 ||
		X509_gmtime_adj(X509_get_notAfter(x509), 365*10) == 0 ||
		//X509_set_subject_name(x509, X509_REQ_get_subject_name(req)) == 0 ||
		(tempkey = X509_REQ_get_pubkey(req)) == NULL ||
		(X509_set_pubkey(x509, tempkey)) == 0 ||
		X509_sign(x509, &pkey, EVP_sha256()) == 0)
	{
		printf("failed to create X509 certificate\n");
		return -1;
	}

	/* write private key */

	BIO *out = BIO_new(BIO_s_file());
	char *password = NULL;
	if (BIO_write_filename(out, priv_name) <= 0 ||
		PEM_write_bio_PrivateKey(out, &pkey, EVP_aes_256_cbc(),
		NULL, 0, NULL, password) == 0)
	{
		printf("failed to write private key\n");
		return -1;
	}
	BIO_free_all(out);

	/* write public key */

	out = BIO_new(BIO_s_file());
	if (BIO_write_filename(out, pub_name) <= 0 ||
		PEM_write_bio_X509(out, x509) == 0)
	{
		printf("failed to write public key\n");
		return -1;
	}
	BIO_free_all(out);

	/* free various allocations */

	EVP_PKEY_free(tempkey);
	X509_free(x509);
	X509_REQ_free(req);
	RSA_free(rsa);

	return 0;
}
