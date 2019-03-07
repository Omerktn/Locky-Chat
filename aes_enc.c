#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();


  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;


  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();


  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();


  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;


  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

typedef struct {
    unsigned char *key;
    unsigned char *iv;
}KEYINFO;

typedef struct {
    unsigned char ciphertext[128];
    int ciphertext_len;
}CIPINFO;

CIPINFO* enc(KEYINFO *info, unsigned char *plaintext)
{
  unsigned char *key = (unsigned char *) info->key;
  unsigned char *iv = (unsigned char *) info->iv;

  unsigned char ciphertext[128];
  int ciphertext_len;

  /* Encrypt the plaintext */
  ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                            ciphertext);

  CIPINFO *cip_info = (CIPINFO *) malloc (sizeof(CIPINFO));
  strcpy(cip_info->ciphertext, ciphertext);
  cip_info->ciphertext_len = ciphertext_len;
  return cip_info;
}

char* dec(KEYINFO *info, CIPINFO *cip_info)
{
  unsigned char *key = (unsigned char *) info->key;
  unsigned char *iv = (unsigned char *) info->iv;
  unsigned char decryptedtext[128];

  unsigned char ciphertext[128];
  strcpy(ciphertext, cip_info->ciphertext);
  int ciphertext_len = cip_info->ciphertext_len;

  int decryptedtext_len;

  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

  decryptedtext[decryptedtext_len] = '\0';

  return strdup(decryptedtext);
}
