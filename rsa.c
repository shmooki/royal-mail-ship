#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

long extended_gcd(long a, long b, long *x, long *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }

    long x1, y1;
    long gcd = extended_gcd(b, a % b, &x1, &y1);

    *x = y1;
    *y = x1 - (a / b) * y1;

    return gcd;
}

long mod_inverse(long e, long phi) {
    long x, y;
    long g = extended_gcd(e, phi, &x, &y);
    if (g != 1) return -1;
    long result = (x % phi + phi) % phi;
    return result;
}

int is_prime(long n) {
    if (n <= 1) return 0;
    for (long i = 2; i * i <= n; i++) {
        if (n % i == 0) return 0;
    }
    return 1;
}

long gen_prime(long min, long max) {
    while (1) {
        long candidate = min + rand() % (max - min);
        if (is_prime(candidate)) return candidate;
    }
}

long gcd(long a, long b) {
    while (b != 0) {
        long t = b;
        b = a % b;
        a = t;
    }
    return a;
}

long modexp(long base, long exp, long mod) {
    long result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

extern long *encrypt(const char *plaintext, long e, long n, size_t *out_len) {
    size_t len = strlen(plaintext);
    *out_len = len;

    long *cipher = malloc(len * sizeof(long));
    for (size_t i = 0; i < len; i++) {
        cipher[i] = modexp((unsigned char)plaintext[i], e, n);
    }
    return cipher;
}

extern char *decrypt(const long *cipher, size_t len, long d, long n) {
    char *plain = malloc(len + 1);

    for (size_t i = 0; i < len; i++) {
        plain[i] = (char)modexp(cipher[i], d, n);
    }

    plain[len] = '\0';
    return plain;
}

extern void generate_rsa_keys(long *n, long *e, long *d) {
    long p = gen_prime(100, 300);
    long q = gen_prime(100, 300);

    *n = p * q;
    long phi = (p - 1) * (q - 1);

    long e_candidate = 3;
    while (gcd(e_candidate, phi) != 1) {
        e_candidate++;
    }
    *e = e_candidate;

    *d = mod_inverse(*e, phi);
}