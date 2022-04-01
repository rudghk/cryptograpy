#include <stdio.h> 
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */
    char * number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

void cal_factor(BIGNUM* x, const BIGNUM *x1, const BIGNUM *x2, const BIGNUM *q){
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

    err:
    return NULL;
}
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b){
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
    BIGNUM *y1 = BN_new();
    BIGNUM *y2 = BN_new();

    // 초기화
    if (BN_cmp(tmp_a, tmp_b) < 0) {
      BN_copy(t, tmp_a);
      BN_copy(tmp_a, tmp_b);
      BN_copy(tmp_b, t);
    }
    BN_dec2bn(&x1, "1");
    BN_dec2bn(&y1, "0");
    BN_dec2bn(&x2, "0");
    BN_dec2bn(&y2, "1");

    while (1) {   
          if(!BN_div(q, r, tmp_a, tmp_b, ctx)){   //q=a/b, r=a%b
            goto err;
          }
          cal_factor(x, x1, x2, q);   //x=x1-(x2*q) 
          cal_factor(y, y1, y2, q);   //y=y1-(y2*q)
          
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
          BN_copy(y1, y2);
          BN_copy(y2, y);
    }
    // a|b or b|a인 경우, 둘 중 작은 수가 gcd
    if(BN_is_zero(r)){    
      if (BN_cmp(tmp_a, tmp_b) < 0){  
        BN_copy(r, tmp_a);
        BN_dec2bn(&x, "1");
        BN_dec2bn(&x, "0");
      }
      else{
        BN_copy(r, tmp_b);
        BN_dec2bn(&x, "0");
        BN_dec2bn(&y, "1");         
      }

    }
    // a < b인 경우, x ,y swap
    if(BN_cmp(a, b) < 0){
      BN_copy(t, x);
      BN_copy(x, y);
      BN_copy(y, t);
    }
    // memory free
    if(ctx != NULL) BN_CTX_free(ctx);
    if(q != NULL) BN_free(q);
    if(t != NULL) BN_free(t);
    if(tmp_a != NULL) BN_free(tmp_a);
    if(tmp_b != NULL) BN_free(tmp_b); 
    if(x1 != NULL) BN_free(x1);
    if(x2 != NULL) BN_free(x2);
    if(y1 != NULL) BN_free(y1);
    if(y2 != NULL) BN_free(y2);
    
    return r;
    err:
      return NULL;
      
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *gcd;

        if(argc != 3){
                printf("usage: xeuclid num1 num2");
                return -1;
        }
        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&b, argv[2]);
        gcd = XEuclid(x,y,a,b);

        printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);

        return 0;
}