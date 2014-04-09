#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "des.h"
#include "des_tables.h"
static long long SubKey[16]={0};
/**
    For the S-box calculation
    Input llt, the 48bit data
    Output res,the 32bit data calculated
*/
ULL S_calc(ULL llt)
{
	int i,x,y;
	ULL res=0;
	for (i=0; i<8; i++)
	{
	    res<<=4;
		ULL tmp=llt-((llt>>6)<<6);
		y=(((tmp&POWLL(5))?1:0)<<1)+(tmp&1);
		x=(tmp%POWLL(5))>>1;
		res+=S_Box[i][y][x];
		llt>>=6;
	}
	return res;
}
/**
    For the function Y=F(X,k) encryption
    Input llt, the 32bit data X
    Input key, the 48bit key k
    Output Y,the 32bit data output
*/
ULL F_calc(ULL llt,ULL key)
{
	llt=E_trans(llt)^key;
	llt=S_calc(llt);
	return P_trans(llt);
}
/**
    For the generation of the subkey
    Input llt, the 28bit data to be looped
    Input move, the integer shows how many digit to loop
*/
ULL loop_move(ULL llt,int move)
{
	llt<<=move;
	if (move == 2)
		llt|=(llt&POWLL(29))?2:0;
	llt|=(llt&POWLL(28))?1:0;
	llt%=POWLL(28);
    return llt;
}
/**
    For the translation of the P table
    Input llt, the 32bit data to be translated
*/
ULL P_trans(ULL llt)
{
	int i;
	ULL tmp=0;
	for (i=0; i<32; i++)
	{
	    tmp<<=1;
		if (llt&POWLL(32-P_Table[i]))
			tmp|=1;
	}
	return tmp;
}
/**
    For the translation of the IP table
    Input llt, the 64bit data to be translated
*/
ULL IP_trans(ULL llt)
{
	int i,j;
	ULL tmp=0;
	for (i=0; i<64; i++)
	{
	    tmp<<=1;
		if (llt&POWLL(64-IP_Table[i]))
			tmp|=1;
	}
	return tmp;
}
/**
    For the translation of the IP-1 table
    Input llt, the 64bit data to be translated
*/
ULL IPR_trans(ULL llt)
{
	int i;
	ULL tmp=0;
	for (i=0; i<64; i++)
	{
	    tmp<<=1;
		if (llt&POWLL(64-IPR_Table[i]))
			tmp|=1;
	}
	return tmp;
}
/**
    For the translation of the E table
    Input llt, the 32bit data to be extended
    Output tmp, the 48bit data extended
*/
ULL E_trans(ULL llt)
{
	int i;
	ULL tmp=0;
	for (i=0; i<48; i++)
	{
	    tmp<<=1;
		if (llt&POWLL(48-E_Table[i]))
			tmp|=1;
	}
	return tmp;
}
/**
    For the translation of the PC1 table
    Input llt, the 64bit data to be compressed
    Output tmp, the 56bit data compressed
*/
ULL PC1_trans(ULL llt)
{
	int i;
	ULL tmp=0;
	for (i=0; i<56; i++)
	{
	    tmp<<=1;
		if (llt&POWLL(56-PC1_Table[i]))
			tmp|=1;
	}
	return tmp;
}
/**
    For the translation of the PC2 table
    Input llt, the 64bit data to be compressed
    Output tmp, the 56bit data compressed
*/
ULL PC2_trans(ULL llt)
{
	int i;
	ULL tmp=0;
	for (i=0; i<48; i++)
	{
		if (llt&POWLL(48-PC2_Table[i]))
			tmp|=1;
        if (i != 48)
            tmp<<=1;
	}
	return tmp;
}
/**
    Generate the subkey
    Input text[8], user's key
    Output null, subkey saved in the array SubKey
*/
void set_key(char text[8])
{
	int i;
	ULL llt=0;
	for (i=0; i<8; i++)
	    llt<<=8,llt+=text[i];
	ULL pc1=PC1_trans(llt);
	for (i=0; i<16; i++)
	{
		ULL lpc1=loop_move(pc1>>28,Move_Table[i]);
		ULL rpc1=loop_move(pc1-(lpc1<<28),Move_Table[i]);
		pc1=(lpc1<<28)+rpc1;
		SubKey[i]=PC2_trans(pc1);
	}
}
/**
    The encrypt function
    Input *text, the data to be encrypted
    Input *cipher, for saving the encrypted data
    Output 1 or 0, shows the result of the encryption
*/
int des_encrypt(char *text, char *cipher)
{
	int i,j,lcb;
	int l_text=strlen(text);
    	//Count the blocks of the cipher
	int l_cipher_blocks=l_text/8+(l_text%8!=0);
		//Request memories for the cipher text
	char * t_cipher=(char *)malloc(sizeof(char)*8*l_cipher_blocks+1);
	*t_cipher='\0';
	lcb=0;
	for (i=0; i<l_cipher_blocks; i++)
	{
	    ULL in=0;
	    for (j=0; j<8; j++)
            in<<=8,in+=(i*8+j >= l_text)?'\0':text[i*8+j];
        ULL out=get_des(in);
        for (j=7; j>=0; j--)
        {
            t_cipher[lcb++]=(char)(out>>(j*8));
            printf("%x ",(char)(out>>(j*8)));
        }
        printf("\n");
        t_cipher[lcb]='\0';
	}
	strcpy(cipher,t_cipher);
	free(t_cipher);
	return 1;
}
/**
    The decrypt function
    Input *text, the data to be decrypted
    Input *cipher, for saving the decrypted data
    Output 1 or 0, shows the result of the decryption
*/
int des_decrypt(char *text, char *cipher)
{
    int i,j,lcb;
	int l_text=strlen(text);
    	//Count the blocks of the cipher
	int l_cipher_blocks=l_text/8;
		//Request memories for the cipher text
	char * t_cipher=(char *)malloc(sizeof(char)*8*l_cipher_blocks+1);
	*t_cipher='\0';
	lcb=0;
	for (i=0; i<l_cipher_blocks; i++)
	{
	    ULL in=*((ULL *)text);
	    for (j=0; j<8; j++)
        {
            in<<=8,in|=((ULL)text[i*8+j])%POWLL(8);
        }
        ULL out=rev_des(in);
        for (j=7; j>=0; j--)
            t_cipher[lcb++]=(char)(out>>(j*8));
        t_cipher[lcb]='\0';
	}
	strcpy(cipher,t_cipher);
	free(t_cipher);
	return 1;
}
/**
    Encrypt a single 64bit data
    Input text, a 64bit unsigned long long data
    Output text_ll, the result
*/
ULL get_des(ULL text)
{
	int i;
	ULL text_ll=text;
	text_ll=IP_trans(text_ll);
	for (i=0; i<16; i++)
	{
		ULL ltext=text_ll>>32;
		ULL rtext=text_ll%POWLL(32);
		ULL tmp=rtext;
		rtext=F_calc(rtext,SubKey[i]);
		rtext=rtext^ltext;
		ltext=tmp;
		text_ll=(ltext<<32)+rtext;
	}
	text_ll=IPR_trans(text_ll);
	return text_ll;
}
/**
    Decrypt a single 64bit data
    Input text, a 64bit unsigned long long data
    Output text_ll, the result
*/
ULL rev_des(ULL text)
{
	int i;
	ULL text_ll=text;
	text_ll=IP_trans(text_ll);
	for (i=15; i>=0; i--)
	{
		ULL ltext=text_ll>>32;
		ULL rtext=text_ll%POWLL(32);
		ULL tmp=ltext;
		ltext=F_calc(ltext,SubKey[i]);
		ltext=ltext^rtext;
		rtext=tmp;
		text_ll=(ltext<<32)+rtext;
	}
	text_ll=IPR_trans(text_ll);
	return text_ll;
}
