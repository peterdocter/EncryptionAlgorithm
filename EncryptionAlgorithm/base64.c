#include <stdio.h>


char base64_table[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline char get_index(char c)
{
    if((c >= 'A') && (c <= 'Z'))
       return c-'A';
    else if((c >= 'a') && (c <= 'z'))
       return c-'a'+26;
    else if((c >= '0') && (c <= '9'))
       return c-'0'+52;
    else if(c == '+')
       return 62;
    else if(c == '/')
       return 63;
    else if(c == '=')
       return 0;
    return 0;
}
int base64_encode(char *text,char *cipher)
{
    int lt=strlen(text),ltt,i,j;
    int roll=0;
    j=lt+(3-lt%3)%3;
    ltt=(j/3)*4;

    char *t_cipher=(char *)malloc(sizeof(char)*(ltt+1));
    t_cipher[ltt]='\0';
    int tmp=0;

    for (i=ltt-1,j--; i>=0; i--,j--)
    {
        if (roll == 0)
            tmp+=((int)(j>=lt?0:text[j]))&255;
        else if (roll == 1)
            tmp+=((((int)(j>=lt?0:text[j]))&255)<<2);
        else if (roll == 2)
            tmp+=((((int)(j>=lt?0:text[j]))&255)<<4);
        else
            roll=-1,j++;
        t_cipher[i]=base64_table[(tmp&63)];
        tmp>>=6;
        roll++;
    }
    lt%=3;
    if (lt == 1)
        t_cipher[ltt-2]='=',lt++;
    if (lt == 2)
        t_cipher[ltt-1]='=';
    strcpy(cipher,t_cipher);
    free(t_cipher);
    return 1;
}
int base64_decode(char *text,char *cipher)
{
    int lt=strlen(text),ltt,ce,i,j;
    if (lt%3 != 0)
        return 0;
    ce=0;
    if (text[lt-1] == '=')  ce++;
    if (text[lt-2] == '=')  ce++;
    ltt=(lt/4)*3;
    for (i=0; i<lt; i++)
        text[i]=get_index(text[i]);
    char *t_cipher=(char *)malloc(sizeof(char)*ltt);
    int roll=0,tmp=0;

    for (i=ltt-1,j=lt-1; i>=0; i--,j--)
    {
        if (roll == 0)
        {
            tmp+=(((int)text[j])&63)+((((int)text[j-1])&63)<<6);
            j--;
        }
        else if (roll == 1)
            tmp+=(((int)text[j])&63)<<4;
        else if (roll == 2)
        {
            tmp+=(((int)text[j])&63)<<2;
            roll=-1;
        }
        t_cipher[i]=(tmp&255);
        tmp>>=8;
        roll++;
    }
    ltt-=ce;
    t_cipher[ltt]='\0';
    strcpy(cipher,t_cipher);
    free(t_cipher);
    return 1;
}
