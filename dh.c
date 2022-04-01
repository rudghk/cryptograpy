// gcc dh.c -L.. -lcrypto  -I../include/crypto -o dh
#include <stdio.h>
#include <openssl/bn.h>

#define knownPrime 599
char *primeTable[knownPrime] = {
    "3", "5", "7", "11", "13", "17", "19", "23", "29",
    "31", "37", "41", "43", "47", "53", "59", "61", "67", "71",
    "73", "79", "83", "89", "97", "101", "103", "107", "109", "113",
    "127", "131", "137", "139", "149", "151", "157", "163", "167", "173",
    "179", "181", "191", "193", "197", "199", "211", "223", "227", "229",
    "233", "239", "241", "251", "257", "263", "269", "271", "277", "281",
    "283", "293", "307", "311", "313", "317", "331", "337", "347", "349",
    "353", "359", "367", "373", "379", "383", "389", "397", "401", "409",
    "419", "421", "431", "433", "439", "443", "449", "457", "461", "463",
    "467", "479", "487", "491", "499", "503", "509", "521", "523", "541",
    "547", "557", "563", "569", "571", "577", "587", "593", "599", "601",
    "607", "613", "617", "619", "631", "641", "643", "647", "653", "659",
    "661", "673", "677", "683", "691", "701", "709", "719", "727", "733",
    "739", "743", "751", "757", "761", "769", "773", "787", "797", "809",
    "811", "821", "823", "827", "829", "839", "853", "857", "859", "863",
    "877", "881", "883", "887", "907", "911", "919", "929", "937", "941",
    "947", "953", "967", "971", "977", "983", "991", "997", "1009", "1013",
    "1019", "1021", "1031", "1033", "1039", "1049", "1051", "1061", "1063", "1069",
    "1087", "1091", "1093", "1097", "1103", "1109", "1117", "1123", "1129", "1151",
    "1153", "1163", "1171", "1181", "1187", "1193", "1201", "1213", "1217", "1223",
    "1229", "1231", "1237", "1249", "1259", "1277", "1279", "1283", "1289", "1291",
    "1297", "1301", "1303", "1307", "1319", "1321", "1327", "1361", "1367", "1373",
    "1381", "1399", "1409", "1423", "1427", "1429", "1433", "1439", "1447", "1451",
    "1453", "1459", "1471", "1481", "1483", "1487", "1489", "1493", "1499", "1511",
    "1523", "1531", "1543", "1549", "1553", "1559", "1567", "1571", "1579", "1583",
    "1597", "1601", "1607", "1609", "1613", "1619", "1621", "1627", "1637", "1657",
    "1663", "1667", "1669", "1693", "1697", "1699", "1709", "1721", "1723", "1733",
    "1741", "1747", "1753", "1759", "1777", "1783", "1787", "1789", "1801", "1811",
    "1823", "1831", "1847", "1861", "1867", "1871", "1873", "1877", "1879", "1889",
    "1901", "1907", "1913", "1931", "1933", "1949", "1951", "1973", "1979", "1987",
    "1993", "1997", "1999", "2003", "2011", "2017", "2027", "2029", "2039", "2053",
    "2063", "2069", "2081", "2083", "2087", "2089", "2099", "2111", "2113", "2129",
    "2131", "2137", "2141", "2143", "2153", "2161", "2179", "2203", "2207", "2213",
    "2221", "2237", "2239", "2243", "2251", "2267", "2269", "2273", "2281", "2287",
    "2293", "2297", "2309", "2311", "2333", "2339", "2341", "2347", "2351", "2357",
    "2371", "2377", "2381", "2383", "2389", "2393", "2399", "2411", "2417", "2423",
    "2437", "2441", "2447", "2459", "2467", "2473", "2477", "2503", "2521", "2531",
    "2539", "2543", "2549", "2551", "2557", "2579", "2591", "2593", "2609", "2617",
    "2621", "2633", "2647", "2657", "2659", "2663", "2671", "2677", "2683", "2687",
    "2689", "2693", "2699", "2707", "2711", "2713", "2719", "2729", "2731", "2741",
    "2749", "2753", "2767", "2777", "2789", "2791", "2797", "2801", "2803", "2819",
    "2833", "2837", "2843", "2851", "2857", "2861", "2879", "2887", "2897", "2903",
    "2909", "2917", "2927", "2939", "2953", "2957", "2963", "2969", "2971", "2999",
    "3001", "3011", "3019", "3023", "3037", "3041", "3049", "3061", "3067", "3079",
    "3083", "3089", "3109", "3119", "3121", "3137", "3163", "3167", "3169", "3181",
    "3187", "3191", "3203", "3209", "3217", "3221", "3229", "3251", "3253", "3257",
    "3259", "3271", "3299", "3301", "3307", "3313", "3319", "3323", "3329", "3331",
    "3343", "3347", "3359", "3361", "3371", "3373", "3389", "3391", "3407", "3413",
    "3433", "3449", "3457", "3461", "3463", "3467", "3469", "3491", "3499", "3511",
    "3517", "3527", "3529", "3533", "3539", "3541", "3547", "3557", "3559", "3571",
    "3581", "3583", "3593", "3607", "3613", "3617", "3623", "3631", "3637", "3643",
    "3659", "3671", "3673", "3677", "3691", "3697", "3701", "3709", "3719", "3727",
    "3733", "3739", "3761", "3767", "3769", "3779", "3793", "3797", "3803", "3821",
    "3823", "3833", "3847", "3851", "3853", "3863", "3877", "3881", "3889", "3907",
    "3911", "3917", "3919", "3923", "3929", "3931", "3943", "3947", "3967", "3989",
    "4001", "4003", "4007", "4013", "4019", "4021", "4027", "4049", "4051", "4057",
    "4073", "4079", "4091", "4093", "4099", "4111", "4127", "4129", "4133", "4139",
    "4153", "4157", "4159", "4177", "4201", "4211", "4217", "4219", "4229", "4231",
    "4241", "4243", "4253", "4259", "4261", "4271", "4273", "4283", "4289", "4297",
    "4327", "4337", "4339", "4349", "4357", "4363", "4373", "4391", "4397", "4409"
};

typedef struct _b10dh_param_st {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
}BOB10_DH_PARAM;

typedef struct _b10dh_keypair_st {
    BIGNUM *prk;
    BIGNUM *puk;
}BOB10_DH_KEYPAIR;

// DH param 구조체를 생성하여 포인터를 리턴하는 함수
BOB10_DH_PARAM *BOB10_DH_PARAM_new(){
    BOB10_DH_PARAM* b10dhp = (BOB10_DH_PARAM*)malloc(sizeof(BOB10_DH_PARAM));
    b10dhp->p = BN_new();
    b10dhp->q = BN_new();
    b10dhp->g = BN_new();
    return b10dhp;
}
// DH keypair 구조체를 생성하여 포인터를 리턴하는 함수
BOB10_DH_KEYPAIR *BOB10_DH_KEYPAIR_new(){
    BOB10_DH_KEYPAIR* b10dhk = (BOB10_DH_KEYPAIR*)malloc(sizeof(BOB10_DH_KEYPAIR));
    b10dhk->prk = BN_new();
    b10dhk->puk = BN_new();
    return b10dhk;
}
// DH param 구조체 포인터를 해제하는 함수
int BOB10_DH_PARAM_free(BOB10_DH_PARAM *b10dhp){
    if(b10dhp->p != NULL) BN_free(b10dhp->p);
    if(b10dhp->q != NULL) BN_free(b10dhp->q);
    if(b10dhp->g != NULL) BN_free(b10dhp->g);
    free(b10dhp);
    return 0;
}
// DH keypair 구조체 포인터를 해제하는 함수
int BOB10_DH_KEYPAIR_free(BOB10_DH_KEYPAIR *b10dhk){
    if(b10dhk->prk != NULL) BN_free(b10dhk->prk);
    if(b10dhk->puk != NULL) BN_free(b10dhk->puk);
    free(b10dhk);
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
        BN_mod_sqr(A, A, m, ctx);
        if(BN_is_bit_set(e, i)){    // bi == 1
            // A = A*a (mod m)
            BN_mod_mul(A, A, a, m, ctx);
        } 
    }
    BN_copy(r, A);

    // memory free
    if(ctx != NULL) BN_CTX_free(ctx);
    if(A != NULL) BN_free(A);

    return 0;
}

// Verify the number is a prime with known prime
int Small_Prime_Test(BIGNUM *p){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *t = BN_new();
    BIGNUM *q = BN_new();

    int isPrime = 1;
    for(int i=0;i<knownPrime;i++){
        BN_dec2bn(&q, primeTable[i]);
        BN_mod(t, p, q, ctx);
        if(BN_is_zero(t)){
            isPrime = 0;
            break;
        }
    }

    if(ctx != NULL) BN_CTX_free(ctx);
    if(t != NULL) BN_free(t);
    if(q != NULL) BN_free(q);
    
    if(isPrime == 1)
        return 0;
    else
        return -1;
}

// Verify the number is a prime
int Miller_Rabin(BIGNUM* p, int num){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *t = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *minus_one = BN_new();
    BIGNUM *t2 = BN_new();
    BN_dec2bn(&one, "1");
    BN_dec2bn(&two, "2");
    BN_dec2bn(&minus_one, "-1");

	// q, k  
    BN_sub(t, p, one);        // t=p-1
	int len = BN_num_bits(t);
    int k=1;
	for(;k<len; k++){     // b1부터 blen-1까지 수행
        if(BN_is_bit_set(t, k)){    // bk == 1
            // q = t/(2**k)
            BN_rshift(q, t, k);
            break;
        } 
    }

    int isPrime = 1;
    for(int i=0;i< num && isPrime==1;i++){
        BN_rand_range(a, p);    // random a
        ExpMod(t, a, q, p);     // t=a**q(mod p)
        if(BN_cmp(t, one)==0 || BN_cmp(t, minus_one)==0)    // t가 1 or -1
            continue;
        int j = 1;
        for(;j<k && isPrime==1;j++){
            ExpMod(t, t, two, p);               // t = a**(q*2**(j)) (mod p)
            if(BN_cmp(t, minus_one)==0)         // t가 -1
                break;
        }
        if(j==k)
            isPrime = 0;
    }

	if(ctx != NULL) BN_CTX_free(ctx);
    if(t != NULL) BN_free(t);
    if(a != NULL) BN_free(a);
    if(q != NULL) BN_free(q);
    if(one != NULL) BN_free(one);
    if(two != NULL) BN_free(two);
    if(minus_one != NULL) BN_free(minus_one);
    if(t2 != NULL) BN_free(t2);

    if(isPrime == 1)
        return 0;
    else
        return -1;
}

int BOB10_DH_ParamGenPQ(BOB10_DH_PARAM *dhp, int pBits, int qBits){
    BIGNUM *one = BN_new(); 
	BN_dec2bn(&one, "1"); 
	BIGNUM *two = BN_new(); 
	BN_dec2bn(&two, "2"); 
    BIGNUM *j = BN_new(); 
	BN_CTX *ctx = BN_CTX_new();	
    // BIGNUM *rangeQBits = BN_new();
	// BN_dec2bn(&rangeQBits, "0");
    // BN_set_bit(rangeQBits, qBits+1);      // rangeBits=100...00 // bit 수 유지기
	// BIGNUM *rangePQBits = BN_new();
	// BN_dec2bn(&rangePQBits, "0");
    // BN_set_bit(rangePQBits, pBits-qBits+1);

	int isPrime = 0;
	
	while(!isPrime){
        // Choose odd number q randomly
        BN_rand(dhp->q, qBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        if(!BN_is_odd(dhp->q))        // dhp->q is odd
            BN_add(dhp->q, dhp->q, one);  // q=q+1

        // Choose prime number q
        while(1){
            if(Small_Prime_Test(dhp->q) == 0){
                if(Miller_Rabin(dhp->q, 10) == 0)    // q is prime
                    break;
            }
            BN_add(dhp->q, dhp->q, two);        // q = q+2
            // // qBits 수 유지
            // if(!BN_mod(dhp->q, dhp->q, rangeQBits, ctx))    
            //     goto err;
        }

        // Choose even number j randomly
        BN_rand(j, pBits-qBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        if(BN_is_odd(j))        // j is odd
            BN_add(j, j, one);  // j=j+1

		while(1){
			// p=q*j+1
			BN_mul(dhp->p, dhp->q, j, ctx);
			BN_add(dhp->p, dhp->p, one);
            // Choose prime number p
            if(Small_Prime_Test(dhp->p) == 0){
                if(Miller_Rabin(dhp->p, 3) == 0){       // p is prime
                    isPrime = 1;
                    break;
                }
            }
            // p is not prime
            BN_add(j, j, two);        // j=j+2
            // // pBits-qBits 수 유지
            // if(!BN_mod(j, j, rangePQBits, ctx))    
            //     goto err;
		}
	}
	if(ctx != NULL) BN_CTX_free(ctx);
	if(one != NULL) BN_free(one);
	if(two != NULL) BN_free(two);
	if(j != NULL) BN_free(j);
    // if(rangeQBits != NULL) BN_free(rangeQBits);
    // if(rangePQBits != NULL) BN_free(rangePQBits);

	return 0;
}
// Generate g
int BOB10_DH_ParamGenG(BOB10_DH_PARAM *dhp){
    BIGNUM *t = BN_new();    
    BIGNUM *t2 = BN_new(); 
    BIGNUM *t3 = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_dec2bn(&t3, "1");      
    BN_sub(t, dhp->p, t3);  // t=p-1
    BN_dec2bn(&t3, "2");          
    BN_div(t2, t3, t, t3, ctx);     // t2=(p-1)/2

    // Get primitive g
    while(1){
        // Get any g in range F_p
        BN_rand_range(dhp->g, dhp->p);
        ExpMod(t3, dhp->g, t2, dhp->p);     // t3=g**((p-1)/2) (mod p)
        if(BN_cmp(t3, t) == 0)
            break;
    }
    // Get g which is ord g = q
    BN_div(t2, t3, t, dhp->q, ctx);     // t2=(p-1)/q
    ExpMod(dhp->g, dhp->g, t2, dhp->p);     // g=g**((p-1)/q) (mod p)

    if(ctx != NULL) BN_CTX_free(ctx);
    if(t != NULL) BN_free(t);
    if(t2 != NULL) BN_free(t2);
    if(t3 != NULL) BN_free(t3);

    return 0;
}
// Generate private and public key
int BOB10_DH_KeypairGen(BOB10_DH_KEYPAIR *dhk,BOB10_DH_PARAM *dhp){
	// Choose secret key
	BN_rand_range(dhk->prk, dhp->q);	// q 미만의 수
	// dhk->puk = g**(dhk->prk) mod p
	ExpMod(dhk->puk, dhp->g, dhk->prk, dhp->p);
	return 0;
}
// sharedSecret = peerKey**dhk->prk (mod dhp->p) = y**prk (mod p)
int BOB10_DH_Derive(BIGNUM *sharedSecret, BIGNUM *peerKey, BOB10_DH_KEYPAIR *dhk, BOB10_DH_PARAM *dhp){
	ExpMod(sharedSecret, peerKey, dhk->prk, dhp->p);
    return 0;
}

int main (int argc, char *argv[]) 
{
	BIGNUM *sharedSecret = BN_new();
	BOB10_DH_PARAM *dhp = BOB10_DH_PARAM_new();
	BOB10_DH_KEYPAIR *aliceK = BOB10_DH_KEYPAIR_new();
	BOB10_DH_KEYPAIR *bobK = BOB10_DH_KEYPAIR_new();

	BOB10_DH_ParamGenPQ(dhp, 2048, 256); // test : 256, 64
	printf("p=0x");BN_print_fp(stdout,dhp->p);printf("\n");
	printf("q=0x");BN_print_fp(stdout,dhp->q);printf("\n");
	BOB10_DH_ParamGenG(dhp);
	printf("g=0x");BN_print_fp(stdout,dhp->g);printf("\n");

	BOB10_DH_KeypairGen(aliceK,dhp);
	printf("alicePuk=0x");BN_print_fp(stdout,aliceK->puk);printf("\n");
	printf("alicePrk=0x");BN_print_fp(stdout,aliceK->prk);printf("\n");

	BOB10_DH_KeypairGen(bobK,dhp);
	printf("bobPuk=0x");BN_print_fp(stdout,bobK->puk);printf("\n");
	printf("bobPrk=0x");BN_print_fp(stdout,bobK->prk);printf("\n");


	BOB10_DH_Derive(sharedSecret, bobK->puk, aliceK, dhp);
	printf("SS1=0x");BN_print_fp(stdout,sharedSecret);printf("\n");
	BOB10_DH_Derive(sharedSecret, aliceK->puk, bobK, dhp);
	printf("SS2=0x");BN_print_fp(stdout,sharedSecret);printf("\n");

	BOB10_DH_PARAM_free(dhp);
	BOB10_DH_KEYPAIR_free(aliceK);
	BOB10_DH_KEYPAIR_free(bobK);
	BN_free(sharedSecret);

	return 0;
}
