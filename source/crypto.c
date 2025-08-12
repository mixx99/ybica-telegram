#include "crypto.h"
#include "log.h"

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#include <stdio.h>

void initialize_SSL() {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

void destroy_SSL() {
  ERR_free_strings();
  EVP_cleanup();
}

// Extracts the user's uuid from the X509 certificate.
uint32_t get_user_uuid_from_cert() {
  FILE *fp = fopen("crypto/user.crt", "r");
  if (!fp) {
    print_error("Failed to open certificate file to get uuid");
    return 0;
  }
  X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
  fclose(fp);
  if (cert == NULL) {
    print_error("Failed to read certificate to get uuid");
    return 0;
  }

  ASN1_INTEGER *serial = X509_get_serialNumber(cert);
  unsigned char *serial_buf = NULL;
  int serial_len = i2d_ASN1_INTEGER(serial, &serial_buf);
  if (serial_len <= 0) {
    X509_free(cert);
    print_error("Failed to encode serial number to get uuid");
    return 0;
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(serial_buf, serial_len, hash);

  OPENSSL_free(serial_buf);
  X509_free(cert);

  // big-endian
  uint32_t uuid = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
  return uuid;
}

// Checks the user certificate in crypto/user.crt and crypto/ca.crt
int verify_user_certificate() {
  FILE *file = NULL;

  file = fopen("crypto/user.crt", "r");
  if (file == NULL) {
    print_error("Failed to open user.crt");
    return -1;
  }
  X509 *user_cert = PEM_read_X509(file, NULL, NULL, NULL);
  fclose(file);
  if (user_cert == NULL) {
    print_error("Failed to read user.crt");
    return -1;
  }
  X509_STORE *store = NULL;
  store = X509_STORE_new();
  if (store == NULL) {
    print_error("Failed to create a store");
    return -1;
  }
  if (X509_STORE_load_locations(store, "crypto/ca.crt", NULL) != 1) {
    print_error("Failed to load store ca.crt");
    return -1;
  }
  X509_STORE_CTX *context = NULL;
  context = X509_STORE_CTX_new();
  if (context == NULL) {
    print_error("Failed to create a context");
    return -1;
  }
  if (X509_STORE_CTX_init(context, store, user_cert, NULL) != 1) {
    print_error("Failed to init context store");
    return -1;
  }
  int result = 0;
  result = X509_verify_cert(context);

  X509_STORE_CTX_free(context);
  X509_STORE_free(store);
  X509_free(user_cert);
  return result == 1 ? 1 : -1;
}
