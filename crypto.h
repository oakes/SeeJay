#ifdef CRYPTO_H
#define CRYPTO_H

int create_private_key(void **priv_key);
int create_public_key(void **pub_key, void *priv_key);
int read_private_key(void **priv_key, char *name);
int read_public_key(void **pub_key, char *name);
int write_private_key(void *priv_key, char *name);
int write_public_key(void *pub_key, char *name);

int tls_global_init(void **ctx_ptr, void *priv_key, void *pub_key);
int tls_local_init(void **ssl_ptr, void *ctx);

#endif
