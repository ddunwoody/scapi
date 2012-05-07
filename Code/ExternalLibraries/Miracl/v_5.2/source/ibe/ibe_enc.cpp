/*
   Boneh & Franklin's Identity Based Encryption
  
   Encryption phase
  
   Generates a random AES session key, and uses it to encrypt a file.
   Outputs ciphertext <filename>.ibe.

   The session key is IBE encrypted, and written to <filename>.key

   NOTE: Uses Tate Pairing only
   NOTE: New fast Tate pairing algorithm

   Compile as 
   cl /O2 /GX ibe_enc.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
   where miracl is built using the Comba method.

 */

#include <iostream>
#include <fstream>
#include <cstring>
#include "ecn.h"
#include "zzn.h"
#include "ebrick.h"
#include "zzn2.h"

using namespace std;

#define HASH_LEN 32

#define PBITS 512
#define QBITS 160

// Using SHA-256 as basic hash algorithm

//
// Define one or the other of these
//
// Which is faster depends on the I/M ratio - See imratio.c
// Roughly if I/M ratio > 16 use PROJECTIVE, otherwise use AFFINE
//

// #define AFFINE
#define PROJECTIVE

// Define this to use this idea ftp://ftp.computing.dcu.ie/pub/resources/crypto/short.pdf
// which enables denominator elimination
#define SCOTT

//
// Tate Pairing Code
//
// Extract ECn point in internal ZZn format
//

void extract(ECn& A,ZZn& x,ZZn& y)
{ 
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
}

void extract(ECn& A,ZZn& x,ZZn& y,ZZn& z)
{ 
    big t;
    x=(A.get_point())->X;
    y=(A.get_point())->Y;
    t=(A.get_point())->Z;
    if (A.get_status()!=MR_EPOINT_GENERAL) z=1;
    else                                   z=t;
}

//
// Line from A to destination C. Let A=(x,y)
// Line Y-slope.X-c=0, through A, so intercept c=y-slope.x
// Line Y-slope.X-y+slope.x = (Y-y)-slope.(X-x) = 0
// Now evaluate at Q -> return (Qy-y)-slope.(Qx-x)
//

ZZn2 line(ECn& A,ECn& C,ZZn& slope,ZZn2& Qx,ZZn2& Qy)
{ 
    ZZn2 n=Qx,w=Qy;
    ZZn x,y,z,t;
#ifdef AFFINE
    extract(A,x,y);
    n-=x; n*=slope;            // 2 ZZn muls
    w-=y; n-=w;
#endif
#ifdef PROJECTIVE
    extract(A,x,y,z);
    x*=z; t=z; z*=z; z*=t;          
    n*=z; n-=x;                // 9 ZZn muls
    w*=z; w-=y; 
    extract(C,x,y,z);
    w*=z; n*=slope; n-=w;                     
#endif
    return n;
}

#ifndef SCOTT

//
// Vertical line through point A
//

ZZn2 vertical(ECn& A,ZZn2& Qx)
{
    ZZn2 n=Qx;
    ZZn x,y,z;
#ifdef AFFINE
    extract(A,x,y);
    n-=x;
#endif
#ifdef PROJECTIVE
    extract(A,x,y,z);
    z*=z;                    
    n*=z; n-=x;                // 3 ZZn muls
#endif
    return n;
}

#endif

//
// Add A=A+B  (or A=A+A) 
// Bump up num and denom
//
// AFFINE doubling     - 12 ZZn muls, plus 1 inversion
// AFFINE adding       - 11 ZZn muls, plus 1 inversion
//
// PROJECTIVE doubling - 26 ZZn muls
// PROJECTIVE adding   - 34 ZZn muls
//


void g(ECn& A,ECn& B,ZZn2& Qx,ZZn2& Qy,ZZn2& num)
{
    int type;
    ZZn  lam,mQy;
    ZZn2 d,u;
    big ptr;
    ECn P=A;

// Evaluate line from A
    type=A.add(B,&ptr);

#ifndef SCOTT
    if (!type)   { u=vertical(P,Qx); d=1; }
    else
    {
#endif
        lam=ptr;
        u=line(P,A,lam,Qx,Qy);
#ifndef SCOTT
        d=vertical(A,Qx);
    }

    num*=(u*conj(d));    // 6 ZZn muls  
#else
// denominator elimination!
    num*=u;
#endif
}

//
// Tate Pairing 
//

BOOL fast_tate_pairing(ECn& P,ZZn2& Qx,ZZn2& Qy,Big& q,ZZn2& res)
{ 
    int i,nb;
    Big n,p;
    ECn A;


// q.P = 2^17*(2^142.P +P) + P

    res=1;
    A=P;    // reset A

#ifdef SCOTT
// we can avoid last iteration..
    n=q-1;
#else
    n=q;
#endif
    nb=bits(n);

    for (i=nb-2;i>=0;i--)
    {
        res*=res;         
        g(A,A,Qx,Qy,res); 
        if (bit(n,i))
            g(A,P,Qx,Qy,res);       
    }

#ifdef SCOTT
    if (A!=-P || res.iszero()) return FALSE;
#else
    if (!A.iszero()) return FALSE;
#endif

    p=get_modulus();         // get p
    res= pow(res,(p+1)/q);   // raise to power of (p^2-1)/q
    res=conj(res)/res;
    if (res.isunity()) return FALSE;
    return TRUE;   
}

//
// ecap(.) function - apply distortion map
//
// Qx is in ZZn if SCOTT is defined. Qy is in ZZn if SCOTT is not defined. 
// This can be exploited for some further optimisations. 
//

BOOL ecap(ECn& P,ECn& Q,Big& order,ZZn2& cube,ZZn2& res)
{
     ZZn2 Qx,Qy;
     Big xx,yy;
#ifdef SCOTT
     ZZn a,b,x,y,ib,w,t1,y2,ib2;
#else
     ZZn2 lambda,ox;
#endif
     Q.get(xx,yy);
     Qx=(ZZn)xx*cube;
     Qy=(ZZn)yy;

#ifndef SCOTT
// point doubling
     lambda=(3*Qx*Qx)/(Qy+Qy);
     ox=Qx;
     Qx=lambda*lambda-(Qx+Qx);
     Qy=lambda*(ox-Qx)-Qy;
#else
// explicit point subtraction
     Qx.get(a,b);
     y=yy;
     ib=(ZZn)1/b;

     t1=a*b*b;
     y2=y*y;
     ib2=ib*ib;
     w=y2+2*t1;
     x=-w*ib2;
     y=-y*(w+t1)*(ib2*ib);
     Qx.set(x); Qy.set((ZZn)0,y);

#endif

     if (fast_tate_pairing(P,Qx,Qy,order,res)) return TRUE;
     return FALSE;
}


//
// Hash functions
// 

Big H1(char *string)
{ // Hash a zero-terminated string to a number < modulus
    Big h,p;
    char s[HASH_LEN];
    int i,j; 
    sha256 sh;

    shs256_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) break;
        shs256_process(&sh,string[i]);
    }
    shs256_hash(&sh,s);
    p=get_modulus();
    h=1; j=0; i=1;
    forever
    {
        h*=256; 
        if (j==HASH_LEN)  {h+=i++; j=0;}
        else         h+=s[j++];
        if (h>=p) break;
    }
    h%=p;
    return h;
}

int H2(ZZn2 x,char *s)
{ // Hash an Fp2 to an n-byte string s[.]. Return n
    sha256 sh;
    Big a,b;
    int m;

    shs256_init(&sh);
    x.get(a,b);

    while (a>0)
    {
        m=a%256;
        shs256_process(&sh,m);
        a/=256;
    }
    while (b>0)
    {
        m=b%256;
        shs256_process(&sh,m);
        b/=256;
    }
    shs256_hash(&sh,s);

    return HASH_LEN;
}

Big H3(char *x1,char *x2)
{
    sha256 sh;
    char h[HASH_LEN];
    Big a;
    int i;

    shs256_init(&sh);
    for (i=0;i<HASH_LEN;i++)
        shs256_process(&sh,x1[i]);
    for (i=0;i<HASH_LEN;i++)
        shs256_process(&sh,x2[i]);
    shs256_hash(&sh,h);
    a=from_binary(HASH_LEN,h);
    return a;
}

void H4(char *x,char *y)
{ // hashes y=h(x)
    int i;
    sha256 sh;
    shs256_init(&sh);
    for (i=0;i<HASH_LEN;i++)
        shs256_process(&sh,x[i]);
    shs256_hash(&sh,y);
}
   
//
// Given y, get x=(y^2-1)^(1/3) mod p (from curve equation)
//

Big getx(Big y)
{
    Big p=get_modulus();
    Big t=modmult(y+1,y-1,p);   // avoids overflow
    return pow(t,(2*p-1)/3,p);
}
 
//
// MapToPoint
//

ECn map_to_point(char *ID)
{
    ECn Q;
    Big x0,y0=H1(ID);
 
    x0=getx(y0);

    Q.set(x0,y0);

    return Q;
}

void strip(char *name)
{ /* strip off filename extension */
    int i;
    for (i=0;name[i]!='\0';i++)
    {
        if (name[i]!='.') continue;
        name[i]='\0';
        break;
    }
}

int main()
{
    miracl *mip=mirsys(16,0);   // thread-safe ready. (32,0) for 1024 bit p
    ifstream common("common.ibe");
    ifstream plaintext;
    ofstream key_file,ciphertext;
    ECn U,P,Ppub,Qid,infinity;
    ZZn2 gid,cube,w;
    char key[HASH_LEN],pad[HASH_LEN],rho[HASH_LEN],V[HASH_LEN],W[HASH_LEN];
    char ifname[100],ofname[100],ch,iv[16];
    Big p,q,r,x,y,cof;
    int i,bits;
    long seed;
    aes a;

    cout << "Enter 9 digit random number seed  = ";
    cin >> seed;
	irand(seed);

// ENCRYPT

    common >> bits;
    mip->IOBASE=16;
    common >> p >> q;

    cof=(p+1)/q;

    common >> x >> y;
    EBrick B(x,y,(Big)0,(Big)1,p,8,QBITS);   // precomputation based on fixed P, 8-bit window

#ifdef AFFINE
    ecurve(0,1,p,MR_AFFINE);
#endif
#ifdef PROJECTIVE
    ecurve(0,1,p,MR_PROJECTIVE);
#endif

    P.set(x,y);

    common >> x >> y;
    Ppub.set(x,y);

    common >> x >> y;
    cube.set(x,y);

    char id[1000];
    cout << "Enter your correspondents email address (lower case)" << endl;
    cin.get();
    cin.getline(id,1000);

    mip->IOBASE=10;
    Qid=map_to_point(id);

// This can be done before we know the message to encrypt

    if (!ecap(Ppub,Qid,q,cube,gid))      // ** swap argument order
    {                                    // Qid must be second
        cout << "Bad Parameters" << endl;
        exit(0);
    } 

//
// prepare to encrypt file with random session key
//

    for (i=0;i<HASH_LEN;i++) key[i]=(char)brand();
    for (i=0;i<16;i++) iv[i]=i; // set CFB IV

    aes_init(&a,MR_CFB1,16,key,iv);
    
// figure out where input is coming from

    cout << "Text file to be encoded = " ;
    cin >> ifname;

   /* set up input file */
    strcpy(ofname,ifname);
    strip(ofname);
    strcat(ofname,".ibe");
    plaintext.open(ifname,ios::in); 
    if (!plaintext)
    {
        cout << "Unable to open file " << ifname << "\n";
        return 0;
    }
    cout << "encoding message\n";
    ciphertext.open(ofname,ios::binary|ios::out);

// now encrypt the plaintext file

    forever
    { // encrypt input ..
        plaintext.get(ch);
        if (plaintext.eof()) break;
        aes_encrypt(&a,&ch);
        ciphertext << ch;
    }

    aes_end(&a);

//
// Now IBE encrypt the session key
//

    for (i=0;i<HASH_LEN;i++) rho[i]=(char)brand();
//cout << "rho= " << rho << endl;
//cout << "key= " << key << endl;
    r=H3(rho,key)%q;

    B.mul(r,x,y);       // U=r*P
    U.set(x,y);

    w=pow(gid,r);         

//cout << "r= " << r << endl;
//cout << "w= " << w << endl;
    
    H2(w,pad);
//cout << "pad1= " << pad << endl;    
    for (i=0;i<HASH_LEN;i++) 
    {
        V[i]=rho[i]^pad[i];
        pad[i]=0;
    }

//cout << "rho= " << rho << endl;

    H4(rho,rho);


    for (i=0;i<HASH_LEN;i++) 
    {
        W[i]=key[i]^rho[i];
        rho[i]=0;
    }

    strip(ofname);
    strcat(ofname,".key");
    mip->IOBASE=16;
    key_file.open(ofname);
    U.get(x,y);
    key_file << y << endl;
    x=from_binary(HASH_LEN,V);      // output bit strings in handy Big format
    key_file << x << endl;
    x=from_binary(HASH_LEN,W);
    key_file << x << endl;

    return 0;
}


