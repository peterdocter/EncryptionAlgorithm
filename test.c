#include <stdio.h>
#include "des.c"
int main()
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
