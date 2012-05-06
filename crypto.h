#ifdef CRYPTO_H
#define CRYPTO_H

int create_private_key(void **priv_key_ptr);
int create_public_key(void **pub_key_ptr, void *priv_key);
int read_private_key(void **priv_key_ptr, char *name);
int read_public_key(void **pub_key_ptr, char *name);
int write_private_key(void *priv_key, char *name);
int write_public_key(void *pub_key, char *name);
int create_fingerprint(unsigned char **hash_ptr, void *pub_key);

int tls_global_init(void **ctx_ptr, void *priv_key, void *pub_key);
int tls_local_init(void **ssl_ptr, void *ctx, unsigned char *hash);

#endif
