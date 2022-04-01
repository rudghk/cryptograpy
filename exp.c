#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
    int len = BN_num_bits(e);       // e의 bit 수
    BN_CTX *ctx = BN_CTX_new();     
    BIGNUM *A = BN_new();
    BN_copy(A, a);
    
    for(int i=len-2;i>=0;i--){     // bk-1, bk-2, ..., b1, b0 에서 bk-2부터 b0까지 수행
        // A = A^2 (mod m)
        if(!BN_sqr(A, A, ctx)){
            goto err;
        }
        if(!BN_mod(A, A, m, ctx)){ 
            goto err;
        }
        if(BN_is_bit_set(e, i)){    // bi == 1
            // A = A*a (mod m)
            if(!BN_mul(A, A, a, ctx)){
            goto err;
            }
            if(!BN_mod(A, A, m, ctx)){ 
                goto err;
            }
        } 
    }
    BN_copy(r, A);

    // memory free
    if(ctx != NULL) BN_CTX_free(ctx);
    if(A != NULL) BN_free(A);

    return 0;
    err:
    return -1;
}

int main (int argc, char *argv[])
{
    BIGNUM *a = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *res = BN_new();

    if(argc != 4){
            printf("usage: exp base exponent modulus\n");
            return -1;
    }

    BN_dec2bn(&a, argv[1]);
    BN_dec2bn(&e, argv[2]);
    BN_dec2bn(&m, argv[3]);
    printBN("a = ", a);
    printBN("e = ", e);
    printBN("m = ", m);

    ExpMod(res,a,e,m);

    printBN("a**e mod m = ", res);

    if(a != NULL) BN_free(a);
    if(e != NULL) BN_free(e);
    if(m != NULL) BN_free(m);
    if(res != NULL) BN_free(res);

    return 0;
}