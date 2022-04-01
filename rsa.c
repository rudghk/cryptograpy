#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

typedef struct _b10rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB10_RSA;

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

// RSA 구조체를 생성하여 포인터를 리턴하는 함수
BOB10_RSA *BOB10_RSA_new(){
    BOB10_RSA* b10rsa = (BOB10_RSA*)malloc(sizeof(BOB10_RSA));
    b10rsa->e = BN_new();
    b10rsa->d = BN_new();
    b10rsa->n = BN_new();
    return b10rsa;
}

// RSA 구조체 포인터를 해제하는 함수
int BOB10_RSA_free(BOB10_RSA *b10rsa){
    if(b10rsa->e != NULL) BN_free(b10rsa->e);
    if(b10rsa->d != NULL) BN_free(b10rsa->d);
    if(b10rsa->n != NULL) BN_free(b10rsa->n);
    free(b10rsa);
    return 0;
}

// r = a**e mod m
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
    int len = BN_num_bits(e);       // e의 bit 수
    BN_CTX *ctx = BN_CTX_new();     
    BIGNUM *A = BN_new();
    BN_copy(A, a);
    
    for(int i=len-2;i>=0;i--){     // bk-1, bk-2, ..., b1, b0 에서 bk-2부터 b0까지 수행
        // A = A^2 (mod m)
        if(!BN_sqr(A, A, ctx))
            goto err;
        if(!BN_mod(A, A, m, ctx)) 
            goto err;
        if(BN_is_bit_set(e, i)){    // bi == 1
            // A = A*a (mod m)
            if(!BN_mul(A, A, a, ctx))
                goto err;
            if(!BN_mod(A, A, m, ctx))
                goto err;
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

int Miller_Rabin(BIGNUM* p, int pBits){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *t = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *num1 = BN_new();
    BIGNUM *num2 = BN_new();
    BIGNUM *num_1 = BN_new();
    BIGNUM *t2 = BN_new();
    BN_hex2bn(&num1, "1");
    BN_hex2bn(&num2, "2");
    BN_hex2bn(&num_1, "-1");
   
    // q, k  
    if(!BN_sub(t, p, num1))        // t=p-1
        goto err;
    int len = BN_num_bits(t);
    int k=1;
    for(; k<len; k++){     // b1부터 blen-1까지 수행
        if(BN_is_bit_set(t, k)){    // bk == 1
            BIGNUM *BNk = BN_new();
            char strk[pBits];
            sprintf(strk, "%x", k);
            BN_hex2bn(&BNk, strk); 
            ExpMod(t2, num2, BNk, p);     // t2=2**k
            if(!BN_div(q, t2, t, t2, ctx))  // q=t/t2
                goto err;
            if(BNk != NULL) BN_free(BNk);
            break;
        } 
    }

    int isPrime = 1;  
    for(int i=0;i<10 && isPrime==1;i++){
        if(!BN_rand(a, pBits, -1, 0))   // random a
            goto err;
        ExpMod(t, a, q, p);     // t=a**q (mod p)
        if(BN_cmp(t, num1)==0 || BN_cmp(t, num_1)==0)    // t가 1 or -1
            continue;
        int i = 1;
        for(i=1;i<k && isPrime==1;i++){
            ExpMod(t, t, num2, p);     // t = a**(q*2**(i)) (mod p)
            if(BN_cmp(t, num_1)==0)    // t가 -1
                break;
        }
        if(i == k)
            isPrime = 0;
    }

    if(ctx != NULL) BN_CTX_free(ctx);
    if(t != NULL) BN_free(t);
    if(a != NULL) BN_free(a);
    if(q != NULL) BN_free(q);
    if(num1 != NULL) BN_free(num1);
    if(num2 != NULL) BN_free(num2);
    if(num_1 != NULL) BN_free(num_1);
    if(t2 != NULL) BN_free(t2);

    if(isPrime == 1)
        return 0;
    else
        return -1;

    err:
        return -1;
}

BIGNUM *GenProbPrime(int pBits){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(); 
    if(!BN_rand(p, pBits, 0, 1))
        goto err;

    // 소수 판정&아니면 +2& 소수 판정@@
    BIGNUM *t = BN_new(); 
    BN_hex2bn(&t, "2");
    BIGNUM *t2 = BN_new();
    BN_set_bit(t2, pBits);      // t2=100...00

    while(Miller_Rabin(p, pBits) == -1){
        if(!BN_add(p, p, t))    // p=p+2
            goto err;
        if(!BN_mod(p,p,t2, ctx))
            goto err;
    }

    printBN("prime : ", p);
    if(ctx != NULL) BN_CTX_free(ctx);
    if(t != NULL) BN_free(t);
    if(t2 != NULL) BN_free(t2);

    return p;
    err:
      return NULL;
}

int cal_factor(BIGNUM* x, const BIGNUM *x1, const BIGNUM *x2, const BIGNUM *q){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *t = BN_new();
    if(!BN_mul(t, x2, q, ctx)){
      goto err;
    }
    if(!BN_sub(x, x1, t)){
      goto err;
    }
    if(ctx != NULL) BN_CTX_free(ctx);
    if(t != NULL) BN_free(t);

    return 0;
    err:
        return -1;
}

// y 안씀, b는 a와 서로소인지 검증할 대상
// a에 대한 x값 구하고, gcd 반환 => 즉, a 중심으로 a에 관한 값만 구함
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b){
    // y 안씀, b는 m
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new();
    BIGNUM *t = BN_new();

    BIGNUM *tmp_a = BN_new();
    BIGNUM *tmp_b = BN_new();
    BIGNUM *q = BN_new();
    BN_copy(tmp_a, a);
    BN_copy(tmp_b, b);

    BIGNUM *x1 = BN_new();
    BIGNUM *x2 = BN_new();

    // 초기화
    if (BN_cmp(tmp_a, tmp_b) < 0) {
        BN_copy(t, tmp_a);
        BN_copy(tmp_a, tmp_b);
        BN_copy(tmp_b, t);
        BN_dec2bn(&x1, "0");
        BN_dec2bn(&x2, "1");
    } 
    else{
        BN_dec2bn(&x1, "1");
        BN_dec2bn(&x2, "0");
    }

    while (1) {   
          if(!BN_div(q, r, tmp_a, tmp_b, ctx)){   //q=a/b, r=a%b
            goto err;
          }
          cal_factor(x, x1, x2, q);   //x=x1-(x2*q) 
          
          if(BN_is_zero(r)) { // a|b or b|a
            break;
          }
          if(!BN_mod(t,tmp_b,r,ctx)){ // 다음 r=0
            goto err;
          }          
          if(BN_is_zero(t)) break;
          
          BN_copy(tmp_a,tmp_b);
          BN_copy(tmp_b,r);
          BN_copy(x1, x2);
          BN_copy(x2, x);
    }
    // a|b or b|a인 경우, 둘 중 작은 수가 gcd
    if(BN_is_zero(r)){    
      if (BN_cmp(tmp_a, tmp_b) < 0){  
        BN_copy(r, tmp_a);
      }
      else
        BN_copy(r, tmp_b);       
    }

    // memory free
    if(ctx != NULL) BN_CTX_free(ctx);
    if(q != NULL) BN_free(q);
    if(t != NULL) BN_free(t);
    if(tmp_a != NULL) BN_free(tmp_a);
    if(tmp_b != NULL) BN_free(tmp_b); 
    if(x1 != NULL) BN_free(x1);
    if(x2 != NULL) BN_free(x2);
    
    return r;
    err:
      return NULL;   
}

// RSA 키 생성 함수
// 입력 : nBits (RSA modulus bit size)
// 출력 : b10rsa (구조체에 n, e, d 가  생성돼 있어야 함)
int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits){
    // choose p, q
    BIGNUM *p = BN_new(); 
    BIGNUM *q = BN_new(); 
    unsigned int pBits = nBits/2;
    p = GenProbPrime(pBits);
    q = GenProbPrime(pBits);

    // compute n (n=pq)
    BN_CTX *ctx = BN_CTX_new();
    if(!BN_mul(b10rsa->n, p, q, ctx)){
      goto err;
    }

    // compute phi_n (phi_n=(p-1)(q-1))
    BIGNUM *phi_n = BN_new(); 
    BIGNUM *t = BN_new(); 
    BN_hex2bn(&t, "1");

    if(!BN_sub(p, p, t)){   // p=p-1
      goto err;
    }
    if(!BN_sub(q, q, t)){   // q=q-1
      goto err;
    }
    if(!BN_mul(phi_n, p, q, ctx)){
      goto err;
    }

    // choose e, compute d
    BIGNUM *gcd = BN_new(); 
    char* e_candidate[4] ={"3", "7", "11", "10001"};    // (10진수) 3, 10, 17, 65537
    for(int i=3;i>=0;i--){
        BN_hex2bn(&b10rsa->e, e_candidate[i]);              // choose e
        gcd = XEuclid(b10rsa->d, t, b10rsa->e, phi_n);      // compute d 
        if(BN_is_one(gcd)){             // check (e, phi_n) = 1
            BN_hex2bn(&t, "0");
            if(BN_cmp(b10rsa->d, t) < 0){       // d가 음수인 경우
                if(!BN_add(b10rsa->d, b10rsa->d, phi_n))
                    goto err;
                if(!BN_mod(b10rsa->d, b10rsa->d, phi_n, ctx)) 
                    goto err;
            }
            break;
        } 
    }

    if(p != NULL) BN_free(p);
    if(q != NULL) BN_free(q);
    if(ctx != NULL) BN_CTX_free(ctx);
    if(phi_n != NULL) BN_free(phi_n);
    if(t != NULL) BN_free(t);
    if(gcd != NULL) BN_free(gcd);

    return 0;
    err:
      return -1;
}

// RSA 암호화 함수
int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa){
    if(ExpMod(c, m, b10rsa->e, b10rsa->n) == 0){
        printf("c = ");
        // printBN("c = ", c);
        return 0;
    }
    return -1;
}

// RSA 복호화 함수
int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa){
    if(ExpMod(m, c, b10rsa->d, b10rsa->n) == 0){
        printf("m = ");
        // printBN("m = ", m);
        return 0;
    }
    return -1;
}

int main (int argc, char *argv[])
{   
    BOB10_RSA *b10rsa = BOB10_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();
    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB10_RSA_KeyGen(b10rsa, 1024);
        BN_print_fp(stdout,b10rsa->n);
        printf(" ");
        BN_print_fp(stdout,b10rsa->e);
        printf(" ");
        BN_print_fp(stdout,b10rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b10rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b10rsa->e, argv[2]);
            BOB10_RSA_Enc(out,in, b10rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b10rsa->d, argv[2]);
            BOB10_RSA_Dec(out,in, b10rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }
    printf("\n");
    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b10rsa!= NULL) BOB10_RSA_free(b10rsa);

    return 0;
}

