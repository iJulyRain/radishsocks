/*
 * =====================================================================================
 *
 *       Filename:  cipher.c
 *
 *    Description:  cipher
 *
 *        Version:  1.0
 *        Created:  11/06/2016 01:16:39 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#include "cipher.h"

#include <stdio.h>
#include <string.h>

void rs_encrypt(const unsigned char *in, unsigned char *out, size_t len, const char *key)
{
    int i, j;
    unsigned char c;

    for (i = 0; i < len; i++)
    {
        c = in[i];
        for (j = 0; j < strlen(key); j++)
            c = c ^ key[j];

        out[i] = c;
    }
}
