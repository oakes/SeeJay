#ifdef CRYPTO_H
#define CRYPTO_H

int create_key(void **key);
int read_key(void **key, char *name);
int write_key(void *key, char *name);

#endif
