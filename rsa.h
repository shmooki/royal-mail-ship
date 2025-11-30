#pragma once

#ifndef RSA_H
#define RSA_H

int is_prime(long n);
long gcd(long a, long b);
long modexp(long base, long exp, long mod);
long mod_inverse(long e, long phi);

extern long *encrypt(const char *plaintext, long e, long n, size_t *out_len);
extern char *decrypt(const long *cipher, size_t len, long d, long n);

extern void generate_rsa_keys(long *n, long *e, long *d);

#endif