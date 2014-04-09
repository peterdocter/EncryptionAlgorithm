#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED
#define AES_KEY_NUM 11
#define UC unsigned char
void aes_set_key(UC key[]);

int aes_encrypt(UC *text,UC *cipher);
int aes_get(UC text[][4],UC cipher[][4]);
void aes_sub_bytes(UC text[][4]);
void aes_shift_row(UC text[][4]);
void aes_mix_columns(UC text[][4]);
void aes_add_round_key(UC text[][4], UC keys[][4]);
UC aes_GF_mul_special(UC a, UC b);

int aes_decrypt(UC *text,UC *cipher);
int aes_inv_get(UC text[][4],UC cipher[][4]);
void aes_inv_sub_bytes(UC text[][4]);
void aes_inv_shift_row(UC text[][4]);
void aes_inv_mix_columns(UC text[][4]);
void aes_add_round_key(UC text[][4], UC keys[][4]);
UC aes_GF_mul_normal(UC a, UC b);
#endif // AES_H_INCLUDED
