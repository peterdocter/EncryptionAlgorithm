#include <string.h>
#include <stdlib.h>
#include "aes_tables.h"
#include "aes.h"
UC aes_Expand_Keys[AES_KEY_NUM][4][4];
void aes_set_key(UC key[])
{
    int i,j,k;
    UC tmp[4];
    for (i=0; i<4; i++)
        for (j=0; j<4; j++)
            aes_Expand_Keys[0][i][j]=key[i+j*4];
    for (i=1; i<AES_KEY_NUM; i++)
    {
        aes_Expand_Keys[i][0][0]=aes_Expand_Keys[i-1][0][0]^aes_S_Box[aes_Expand_Keys[i-1][1][3]];
        aes_Expand_Keys[i][1][0]=aes_Expand_Keys[i-1][1][0]^aes_S_Box[aes_Expand_Keys[i-1][2][3]];
        aes_Expand_Keys[i][2][0]=aes_Expand_Keys[i-1][2][0]^aes_S_Box[aes_Expand_Keys[i-1][3][3]];
        aes_Expand_Keys[i][3][0]=aes_Expand_Keys[i-1][3][0]^aes_S_Box[aes_Expand_Keys[i-1][0][3]];
        aes_Expand_Keys[i][0][0]^=aes_Round_Table[i-1];
        for (j=1; j<4; j++)
            for (k=0; k<4; k++)
                aes_Expand_Keys[i][k][j]=aes_Expand_Keys[i-1][k][j]^aes_Expand_Keys[i][k][j-1];
    }
}
int aes_encrypt(UC *text,UC *cipher)
{
    int i,lc,j,k;
    UC tmp[4][4];
    UC t_cipher[16];
    for (j=0; j<4; j++)
        for (k=0; k<4; k++)
            tmp[j][k]=text[k*4+j];
    aes_get(tmp,tmp);
    for (j=0; j<4; j++)
        for (k=0; k<4; k++)
            t_cipher[k*4+j]=tmp[j][k];
    memcpy(cipher,t_cipher,sizeof(t_cipher));
    return 1;
}
int aes_get(UC text[][4],UC cipher[][4])
{
    int i,j,k;
    UC tmp[4][4];
    memcpy(tmp,text,sizeof(tmp));
    aes_add_round_key(tmp,aes_Expand_Keys[0]);
    for (i=1; i<AES_KEY_NUM; i++)
    {
        aes_sub_bytes(tmp);
        aes_shift_row(tmp);
        if (i != 10)
            aes_mix_columns(tmp);
        aes_add_round_key(tmp,aes_Expand_Keys[i]);
    }
    memcpy(cipher,tmp,sizeof(tmp));
}
void aes_sub_bytes(UC text[][4])
{
    int i,j;
    for (i=0; i<4; i++)
        for (j=0; j<4; j++)
            text[i][j]=aes_S_Box[text[i][j]];
}
void aes_shift_row(UC text[][4])
{
    UC tmp[4];
    int i,j;
    for(i=1; i<4; i++)
    {
        for(j=0; j<4; j++)
        {
            tmp[j]=text[i][(i+j)%4];
        }
        for(j=0; j<4; j++)
        {
            text[i][j]=tmp[j];
        }
    }
}

void aes_mix_columns(UC text[][4])
{
    UC tmp[4];
    int i,j;
    for (i=0; i<4; i++)
    {
        for (j=0; j<4; j++)
        {
            tmp[j]=text[j][i];
        }
        for (j=0; j<4; j++)
        {
            text[j][i]=aes_GF_mul_special(0x02,tmp[j])            \
                      ^aes_GF_mul_special(0x03,tmp[(j+1)&3])      \
                      ^aes_GF_mul_special(0x01,tmp[(j+2)&3])      \
                      ^aes_GF_mul_special(0x01,tmp[(j+3)&3]);

        }
    }
}
UC aes_GF_mul_special(UC a, UC b)
{
    UC tmp[2];
    UC res;
    res=0;
    int i;
    tmp[0]=b;
    tmp[1]=b<<1;
    if (tmp[0]&0x80)
        tmp[1]^=0x1b;
    if (a&0x01)
        res^=tmp[0];
    a>>=1;
    if (a&0x01)
        res^=tmp[1];
    return res;
}
UC aes_GF_mul_normal(UC a, UC b)
{
    UC tmp[4];
    UC res=0;
    int i;
    tmp[0]=b;
    for(i=1; i<4; i++)
        tmp[i]=(tmp[i-1]<<1)^((tmp[i-1]&0x80)?0x1b:0);
    for(i=0; i<4; i++)
        res=((a>>i)&0x01)?res^tmp[i]:res;
    return res;
}
void aes_add_round_key(UC text[][4], UC keys[][4])
{
    int i,j;
    for (i=0; i<4; i++)
        for (j=0; j<4; j++)
            text[j][i]^=keys[j][i];
}
int aes_decrypt(UC *text,UC *cipher)
{
    int i,lc,j,k;
    UC tmp[4][4];
    UC t_cipher[16];
    for (j=0; j<4; j++)
        for (k=0; k<4; k++)
            tmp[j][k]=text[k*4+j];
    aes_inv_get(tmp,tmp);
    for (j=0; j<4; j++)
        for (k=0; k<4; k++)
            t_cipher[k*4+j]=tmp[j][k];
    memcpy(cipher,t_cipher,sizeof(t_cipher));
    return 1;
}
int aes_inv_get(UC text[][4],UC cipher[][4])
{
    int i;
    UC tmp[4][4];
    memcpy(tmp,text,sizeof(tmp));
    aes_add_round_key(tmp,aes_Expand_Keys[10]);
    for (i=AES_KEY_NUM-2; i>=0; i--)
    {
        aes_inv_shift_row(tmp);
        aes_inv_sub_bytes(tmp);
        aes_add_round_key(tmp,aes_Expand_Keys[i]);
        if (i)
            aes_inv_mix_columns(tmp);

    }
    memcpy(cipher,tmp,sizeof(tmp));
}
void aes_inv_sub_bytes(UC text[][4])
{
    int i,j;
    for (i=0; i<4; i++)
        for (j=0; j<4; j++)
            text[i][j]=aes_SR_Box[text[i][j]];
}
void aes_inv_shift_row(UC text[][4])
{
    UC tmp[4];
    int i,j;
    for(i=1; i<4; i++)
    {
        for(j=0; j<4; j++)
        {
            tmp[j]=text[i][(j-i+4)%4];
        }
        for(j=0; j<4; j++)
        {
            text[i][j]=tmp[j];
        }
    }
}
void aes_inv_mix_columns(UC text[][4])
{
    UC tmp[4];
    int i,j;
    for (i=0; i<4; i++)
    {
        for (j=0; j<4; j++)
        {
            tmp[j]=text[j][i];
        }
        for (j=0; j<4; j++)
        {
            text[j][i]=aes_GF_mul_normal(0x0e,tmp[j])            \
                      ^aes_GF_mul_normal(0x0b,tmp[(j+1)&3])      \
                      ^aes_GF_mul_normal(0x0d,tmp[(j+2)&3])      \
                      ^aes_GF_mul_normal(0x09,tmp[(j+3)&3]);

        }
    }
}
