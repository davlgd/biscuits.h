#ifdef BS_BUNDLED_CRYPTO

/* ---------------------------------------------------------------------------
 * Ed25519 signature verification
 *
 * VENDORED CODE. The curve and hash arithmetic below is extracted from
 * TweetNaCl, which is public domain:
 *
 *   upstream:  https://tweetnacl.cr.yp.to/20140427/tweetnacl.c
 *   sha256:    02e65bc3013ff2168983365e55906bc783c4c7e0a60d8100f17bb303a17175c4
 *   extracted: the dependency closure of crypto_sign_open, minus the two
 *              functions replaced below -- so no signing, no key generation,
 *              no X25519, no secretbox, no Salsa20, no Poly1305.
 *
 * Writing new curve arithmetic for a project whose selling point is that it
 * can be audited would be a strange way to spend the trust. This is a
 * reviewed implementation, used as-is.
 *
 * Two changes were made, both mechanical and both necessary for a header:
 *
 *   1. Every symbol is prefixed bs_na_ and made static. Upstream declares
 *      file-scope identifiers named A, D, I, K, L, M, R, S, X, Y, Z, u8 and
 *      gf; in a header that a consumer includes, those are a collision
 *      waiting to happen.
 *   2. The `sv` and `FOR` macros are expanded or renamed, for the same reason.
 *
 * The extraction is checked against the RFC 8032 test vectors in
 * tests/unit/test_crypto.c, including rejection cases. If a rename had broken
 * the arithmetic, those vectors would not pass.
 *
 * What is NOT vendored: the ~20 lines that assemble the verification
 * equation, and the streaming SHA-512 around it, both in 46_verify.inc.
 * Upstream's crypto_sign_open requires the caller to hand it one buffer
 * holding signature followed by message, and copies the message out again --
 * two allocations proportional to the input, in a library whose first
 * invariant is that it never allocates. The arithmetic it calls is unchanged;
 * only the order of the calls and the shape of the buffers differ, and the
 * RFC 8032 vectors check the result.
 *
 * This code is held to upstream's style, not to this project's: reformatting
 * vendored cryptography to look tidier is how bugs get introduced. It is
 * excluded from clang-format and its warnings are suppressed locally -- the
 * suppression is scoped to this block and nothing else.
 *
 * Define BISCUITS_NO_BUNDLED_CRYPTO to omit all of it and supply your own
 * verifier through BS_ED25519_VERIFY; see 10_config.inc.
 *
 * Note what is absent: verification needs no entropy. There is no
 * randombytes() here and no CSPRNG dependency anywhere in the library, which
 * is what lets it run on a target that has no source of randomness at all.
 * ------------------------------------------------------------------------ */

/* clang-format off */
/* NOLINTBEGIN */
/* cppcheck-suppress-begin [variableScope,constParameterPointer,constVariablePointer,unreadVariable,shadowVariable,knownConditionTrueFalse,cstyleCast,invalidPointerCast,nullPointerRedundantCheck] */

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#endif

#define BS_NA_FOR(i,n) for (i = 0;i < n;++i)

typedef unsigned char bs_na_u8;
typedef unsigned long bs_na_u32;
typedef unsigned long long bs_na_u64;
typedef long long bs_na_i64;
typedef bs_na_i64 bs_na_gf[16];

static const bs_na_gf
  bs_na_gf0,
  bs_na_gf1 = {1},
  bs_na_D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  bs_na_D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  bs_na_X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  bs_na_Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  bs_na_I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};


static bs_na_u64 bs_na_dl64(const bs_na_u8 *x)
{
  bs_na_u64 i,u=0;
  BS_NA_FOR(i,8) u=(u<<8)|x[i];
  return u;
}


static void bs_na_ts64(bs_na_u8 *x,bs_na_u64 u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}


static int bs_na_vn(const bs_na_u8 *x,const bs_na_u8 *y,int n)
{
  bs_na_u32 i,d = 0;
  BS_NA_FOR(i,n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}


static int bs_na_crypto_verify_32(const bs_na_u8 *x,const bs_na_u8 *y)
{
  return bs_na_vn(x,y,32);
}


static void bs_na_set25519(bs_na_gf r, const bs_na_gf a)
{
  int i;
  BS_NA_FOR(i,16) r[i]=a[i];
}

static void bs_na_car25519(bs_na_gf o)
{
  int i;
  bs_na_i64 c;
  BS_NA_FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

static void bs_na_sel25519(bs_na_gf p,bs_na_gf q,int b)
{
  bs_na_i64 t,i,c=~(b-1);
  BS_NA_FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

static void bs_na_pack25519(bs_na_u8 *o,const bs_na_gf n)
{
  int i,j,b;
  bs_na_gf m,t;
  BS_NA_FOR(i,16) t[i]=n[i];
  bs_na_car25519(t);
  bs_na_car25519(t);
  bs_na_car25519(t);
  BS_NA_FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    bs_na_sel25519(t,m,1-b);
  }
  BS_NA_FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int bs_na_neq25519(const bs_na_gf a, const bs_na_gf b)
{
  bs_na_u8 c[32],d[32];
  bs_na_pack25519(c,a);
  bs_na_pack25519(d,b);
  return bs_na_crypto_verify_32(c,d);
}

static bs_na_u8 bs_na_par25519(const bs_na_gf a)
{
  bs_na_u8 d[32];
  bs_na_pack25519(d,a);
  return d[0]&1;
}

static void bs_na_unpack25519(bs_na_gf o, const bs_na_u8 *n)
{
  int i;
  BS_NA_FOR(i,16) o[i]=n[2*i]+((bs_na_i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

static void bs_na_A(bs_na_gf o,const bs_na_gf a,const bs_na_gf b)
{
  int i;
  BS_NA_FOR(i,16) o[i]=a[i]+b[i];
}

static void bs_na_Z(bs_na_gf o,const bs_na_gf a,const bs_na_gf b)
{
  int i;
  BS_NA_FOR(i,16) o[i]=a[i]-b[i];
}

static void bs_na_M(bs_na_gf o,const bs_na_gf a,const bs_na_gf b)
{
  bs_na_i64 i,j,t[31];
  BS_NA_FOR(i,31) t[i]=0;
  BS_NA_FOR(i,16) BS_NA_FOR(j,16) t[i+j]+=a[i]*b[j];
  BS_NA_FOR(i,15) t[i]+=38*t[i+16];
  BS_NA_FOR(i,16) o[i]=t[i];
  bs_na_car25519(o);
  bs_na_car25519(o);
}

static void bs_na_S(bs_na_gf o,const bs_na_gf a)
{
  bs_na_M(o,a,a);
}

static void bs_na_inv25519(bs_na_gf o,const bs_na_gf i)
{
  bs_na_gf c;
  int a;
  BS_NA_FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    bs_na_S(c,c);
    if(a!=2&&a!=4) bs_na_M(c,c,i);
  }
  BS_NA_FOR(a,16) o[a]=c[a];
}

static void bs_na_pow2523(bs_na_gf o,const bs_na_gf i)
{
  bs_na_gf c;
  int a;
  BS_NA_FOR(a,16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    bs_na_S(c,c);
    if(a!=1) bs_na_M(c,c,i);
  }
  BS_NA_FOR(a,16) o[a]=c[a];
}


static bs_na_u64 bs_na_R(bs_na_u64 x,int c) { return (x >> c) | (x << (64 - c)); }
static bs_na_u64 bs_na_Ch(bs_na_u64 x,bs_na_u64 y,bs_na_u64 z) { return (x & y) ^ (~x & z); }
static bs_na_u64 bs_na_Maj(bs_na_u64 x,bs_na_u64 y,bs_na_u64 z) { return (x & y) ^ (x & z) ^ (y & z); }
static bs_na_u64 bs_na_Sigma0(bs_na_u64 x) { return bs_na_R(x,28) ^ bs_na_R(x,34) ^ bs_na_R(x,39); }
static bs_na_u64 bs_na_Sigma1(bs_na_u64 x) { return bs_na_R(x,14) ^ bs_na_R(x,18) ^ bs_na_R(x,41); }
static bs_na_u64 bs_na_sigma0(bs_na_u64 x) { return bs_na_R(x, 1) ^ bs_na_R(x, 8) ^ (x >> 7); }
static bs_na_u64 bs_na_sigma1(bs_na_u64 x) { return bs_na_R(x,19) ^ bs_na_R(x,61) ^ (x >> 6); }

static const bs_na_u64 bs_na_K[80] = 
{
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};


static int bs_na_crypto_hashblocks(bs_na_u8 *x,const bs_na_u8 *m,bs_na_u64 n)
{
  bs_na_u64 z[8],b[8],a[8],w[16],t;
  int i,j;

  BS_NA_FOR(i,8) z[i] = a[i] = bs_na_dl64(x + 8 * i);

  while (n >= 128) {
    BS_NA_FOR(i,16) w[i] = bs_na_dl64(m + 8 * i);

    BS_NA_FOR(i,80) {
      BS_NA_FOR(j,8) b[j] = a[j];
      t = a[7] + bs_na_Sigma1(a[4]) + bs_na_Ch(a[4],a[5],a[6]) + bs_na_K[i] + w[i%16];
      b[7] = t + bs_na_Sigma0(a[0]) + bs_na_Maj(a[0],a[1],a[2]);
      b[3] += t;
      BS_NA_FOR(j,8) a[(j+1)%8] = b[j];
      if (i%16 == 15)
	BS_NA_FOR(j,16)
	  w[j] += w[(j+9)%16] + bs_na_sigma0(w[(j+1)%16]) + bs_na_sigma1(w[(j+14)%16]);
    }

    BS_NA_FOR(i,8) { a[i] += z[i]; z[i] = a[i]; }

    m += 128;
    n -= 128;
  }

  BS_NA_FOR(i,8) bs_na_ts64(x+8*i,z[i]);

  return n;
}


static const bs_na_u8 bs_na_iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;


static void bs_na_add(bs_na_gf p[4],bs_na_gf q[4])
{
  bs_na_gf a,b,c,d,t,e,f,g,h;
  
  bs_na_Z(a, p[1], p[0]);
  bs_na_Z(t, q[1], q[0]);
  bs_na_M(a, a, t);
  bs_na_A(b, p[0], p[1]);
  bs_na_A(t, q[0], q[1]);
  bs_na_M(b, b, t);
  bs_na_M(c, p[3], q[3]);
  bs_na_M(c, c, bs_na_D2);
  bs_na_M(d, p[2], q[2]);
  bs_na_A(d, d, d);
  bs_na_Z(e, b, a);
  bs_na_Z(f, d, c);
  bs_na_A(g, d, c);
  bs_na_A(h, b, a);

  bs_na_M(p[0], e, f);
  bs_na_M(p[1], h, g);
  bs_na_M(p[2], g, f);
  bs_na_M(p[3], e, h);
}

static void bs_na_cswap(bs_na_gf p[4],bs_na_gf q[4],bs_na_u8 b)
{
  int i;
  BS_NA_FOR(i,4)
    bs_na_sel25519(p[i],q[i],b);
}

static void bs_na_pack(bs_na_u8 *r,bs_na_gf p[4])
{
  bs_na_gf tx, ty, zi;
  bs_na_inv25519(zi, p[2]); 
  bs_na_M(tx, p[0], zi);
  bs_na_M(ty, p[1], zi);
  bs_na_pack25519(r, ty);
  r[31] ^= bs_na_par25519(tx) << 7;
}

static void bs_na_scalarmult(bs_na_gf p[4],bs_na_gf q[4],const bs_na_u8 *s)
{
  int i;
  bs_na_set25519(p[0],bs_na_gf0);
  bs_na_set25519(p[1],bs_na_gf1);
  bs_na_set25519(p[2],bs_na_gf1);
  bs_na_set25519(p[3],bs_na_gf0);
  for (i = 255;i >= 0;--i) {
    bs_na_u8 b = (s[i/8]>>(i&7))&1;
    bs_na_cswap(p,q,b);
    bs_na_add(q,p);
    bs_na_add(p,p);
    bs_na_cswap(p,q,b);
  }
}

static void bs_na_scalarbase(bs_na_gf p[4],const bs_na_u8 *s)
{
  bs_na_gf q[4];
  bs_na_set25519(q[0],bs_na_X);
  bs_na_set25519(q[1],bs_na_Y);
  bs_na_set25519(q[2],bs_na_gf1);
  bs_na_M(q[3],bs_na_X,bs_na_Y);
  bs_na_scalarmult(p,q,s);
}


static const bs_na_u64 bs_na_L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static void bs_na_modL(bs_na_u8 *r,bs_na_i64 x[64])
{
  bs_na_i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * bs_na_L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  BS_NA_FOR(j,32) {
    x[j] += carry - (x[31] >> 4) * bs_na_L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  BS_NA_FOR(j,32) x[j] -= carry * bs_na_L[j];
  BS_NA_FOR(i,32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

static void bs_na_reduce(bs_na_u8 *r)
{
  bs_na_i64 x[64],i;
  BS_NA_FOR(i,64) x[i] = (bs_na_u64) r[i];
  BS_NA_FOR(i,64) r[i] = 0;
  bs_na_modL(r,x);
}


static int bs_na_unpackneg(bs_na_gf r[4],const bs_na_u8 p[32])
{
  bs_na_gf t, chk, num, den, den2, den4, den6;
  bs_na_set25519(r[2],bs_na_gf1);
  bs_na_unpack25519(r[1],p);
  bs_na_S(num,r[1]);
  bs_na_M(den,num,bs_na_D);
  bs_na_Z(num,num,r[2]);
  bs_na_A(den,r[2],den);

  bs_na_S(den2,den);
  bs_na_S(den4,den2);
  bs_na_M(den6,den4,den2);
  bs_na_M(t,den6,num);
  bs_na_M(t,t,den);

  bs_na_pow2523(t,t);
  bs_na_M(t,t,num);
  bs_na_M(t,t,den);
  bs_na_M(t,t,den);
  bs_na_M(r[0],t,den);

  bs_na_S(chk,r[0]);
  bs_na_M(chk,chk,den);
  if (bs_na_neq25519(chk, num)) bs_na_M(r[0],r[0],bs_na_I);

  bs_na_S(chk,r[0]);
  bs_na_M(chk,chk,den);
  if (bs_na_neq25519(chk, num)) return -1;

  if (bs_na_par25519(r[0]) == (p[31]>>7)) bs_na_Z(r[0],bs_na_gf0,r[0]);

  bs_na_M(r[3],r[0],r[1]);
  return 0;
}

#undef BS_NA_FOR

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/* cppcheck-suppress-end [variableScope,constParameterPointer,constVariablePointer,unreadVariable,shadowVariable,knownConditionTrueFalse,cstyleCast,invalidPointerCast,nullPointerRedundantCheck] */
/* NOLINTEND */
/* clang-format on */

#endif /* BS_BUNDLED_CRYPTO */
