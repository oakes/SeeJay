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

int create_key(void ** key) {
	RSA *rsa;
	BIGNUM num;
	bzero(&num, sizeof(num));

	if (BN_set_word(&num, 65537) == 0 ||
		(rsa = RSA_new()) == NULL ||
		RSA_generate_key_ex(rsa, 2048, &num, NULL) == 0)
	{
		printf("failed to generate RSA key\n");
		return -1;
	}
	*key = rsa;

	return 0;
}

/*
 * Reads the private key from the disk.
 */

int read_key(void **key, char *name)
{
	EVP_PKEY *pkey;
	char *buffer;
	BIO *in;

	/* read the key into a pkey */

	if (read_file(name, &buffer) < 0 ||
		(in = BIO_new_mem_buf(buffer, -1)) == NULL ||
		(pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL)) == NULL)
	{
		printf("failed to read the key\n");
		return -1;
	}

	/* interpret it based on the algorithm */

	switch (EVP_PKEY_type(pkey->type)) {
	case EVP_PKEY_RSA:
		*key = EVP_PKEY_get1_RSA(pkey);
		break;
	}

	return 0;
}

/*
 * Writes the private key to the disk.
 */

int write_key(void *key, char *name)
{
	/* turn key into pkey */

	EVP_PKEY pkey;
	bzero(&pkey, sizeof(pkey));
	if (EVP_PKEY_assign_RSA(&pkey, (RSA *)key) == 0) {
		printf("failed to parse the key\n");
		return -1;
	}

	/* write private key */

	BIO *out = BIO_new(BIO_s_file());
	const EVP_CIPHER *enc = NULL; /* EVP_aes_256_cbc(); */
	if (BIO_write_filename(out, name) <= 0 ||
		PEM_write_bio_PrivateKey(out, &pkey, enc, NULL, 0, NULL, NULL) == 0)
	{
		printf("failed to write private key\n");
		return -1;
	}
	BIO_free_all(out);

	return 0;
}
