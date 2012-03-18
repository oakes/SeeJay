#ifdef CRYPTO_H
#define CRYPTO_H

int create_private_key(void **priv_key);
int create_public_key(void **pub_key, void *priv_key);
int read_private_key(void **priv_key, char *name);
int read_public_key(void **pub_key, char *name);
int write_private_key(void *priv_key, char *name);
int write_public_key(void *pub_key, char *name);

int dtls_global_init(void **ctx_ptr, void *priv_key, void *pub_key);
int dtls_client_init(void **ssl_ptr, int sock, void *ctx, void *addr);

#endif
