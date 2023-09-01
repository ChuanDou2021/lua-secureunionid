#include "utils.h"

u_char * hex_dump(u_char *dst, u_char *src, int len)
{
    static char  hex[] = "0123456789abcdef";

    while (len--) {
        *dst++ = hex[*src >> 4];
        *dst++ = hex[*src++ & 0xf];
    }

    return dst;
}

inline static int lookup(u_char c)
{
    switch (c) {
        case '0': 
            return 0;
        case '1': 
            return 1;
        case '2': 
            return 2;
        case '3': 
            return 3;
        case '4': 
            return 4;
        case '5': 
            return 5;
        case '6': 
            return 6;
        case '7': 
            return 7;
        case '8': 
            return 8;
        case '9': 
            return 9;
        case 'a':
        case 'A':
            return 10;
        case 'b':
        case 'B':
            return 11;
        case 'c':
        case 'C':
            return 12;
        case 'd':
        case 'D':
            return 13;
        case 'e':
        case 'E':
            return 14;
        case 'f':
        case 'F':
            return 15;
        default:
            return -1;
    }
}

int hex2bytes(u_char *dst, u_char *src)
{
    for(int i = 0; src[i] != '\0'; i += 2 ) {
        int h = lookup(src[i]);
        int l = lookup(src[i+1]);

        if (-1 == h || -1 == l) {
            return -1;
        }
        
        *dst = h << 4 | l;
        dst++;
    }

    return 0;
}