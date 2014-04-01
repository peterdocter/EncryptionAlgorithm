#ifndef _DES_H_
#define _DES_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tables.h"
typedef unsigned long long ULL;

ULL S_calc(ULL llt);
ULL F_calc(ULL llt,ULL key);
ULL P_trans(ULL llt);
ULL E_trans(ULL llt);
ULL loop_move(ULL llt,int move);
void set_key(char *text);
int des_encrypt(char *text, char *cipher);
ULL IP_trans(ULL llt);
ULL IPR_trans(ULL llt);
ULL PC1_trans(ULL llt);
ULL PC2_trans(ULL llt);
ULL get_des(ULL text);
ULL rev_des(ULL text);
#endif
