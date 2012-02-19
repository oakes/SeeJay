#ifdef CRYPTO_H
#define CRYPTO_H

int create_key(void **key);
int read_key(void **key, char *priv_name);
int write_key(void *key, char *priv_name, char *cert_name);

#endif
