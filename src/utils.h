#ifndef DID_UTILS_H
#define DID_UTILS_H

#define ERROR            -1
#define MAX_INT_T_VALUE  2147483647
typedef unsigned char u_char;

u_char * hex_dump(u_char *dst, u_char*src, int len);
int hex2bytes (u_char *dst, u_char *src);
int encode_base64url(u_char *dst, u_char *src, int len);
int decode_base64url(u_char *dst, u_char *src, int len);

#endif