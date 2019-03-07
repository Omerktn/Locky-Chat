#ifndef AES_ENC_H   /* Include guard */
#define AES_ENC_H
  typedef struct {
      unsigned char *key;
      unsigned char *iv;
  }KEYINFO;

  typedef struct {
      unsigned char ciphertext[128];
      int ciphertext_len;
  }CIPINFO;

  CIPINFO* enc(KEYINFO *info, unsigned char *plaintext);
  char* dec(KEYINFO *info, CIPINFO *cip_info);


#endif
