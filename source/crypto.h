#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

void initialize_SSL();
void destroy_SSL();
int verify_user_certificate();
uint32_t get_user_uuid_from_cert();

#endif
