/*
 * =====================================================================================
 *
 *       Filename:  cipher.h
 *
 *    Description:  cipher header
 *
 *        Version:  1.0
 *        Created:  11/06/2016 01:14:47 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <stdlib.h>

void rs_encrypt(const unsigned char *in, unsigned char *out, size_t len, const char *key);

#endif
