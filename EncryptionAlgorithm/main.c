#include <stdio.h>

#include "des.h"


void print(unsigned char* state)
{
	int i;
	for(i=0; i<16; i++)
	{
		printf("%s%X ",state[i]>15 ? "" : "0", state[i]);
	}
	printf("\n");
}
int testAES()
{
    unsigned char keysssss[] =
	{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	};
   unsigned char input[] =
	{
		0x32, 0x43, 0xf6, 0xa8,
		0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2,
		0xe0, 0x37, 0x07, 0x34,
	};
	printf("Original data   : ");
	print(input);
    aes_set_key(keysssss);
    aes_encrypt(input,input);
    printf("After encrpytion: ");
    print(input);

    aes_decrypt(input,input);
    printf("After decrpytion: ");
    print(input);
}
void testDES()
{
    char t[100]="11111111";
	int i;
	set_key(t);
	scanf("%s",t);
    des_encrypt(t,t);
    printf("密文长度为%d %s\n",strlen(t),t);
    des_decrypt(t,t);
    printf("明文长度为%d %s\n",strlen(t),t);
}
int main()
{
    testAES();
    testDES();
}
