/*
   Boneh & Franklin's Identity Based Encryption  - y2=x^3-3x version

   Extract Phase

   cl /O2 /GX ibe_extx.cpp big.cpp ecn.cpp miracl.lib

   After this program has run the file privatex.ibe contains

   <Private point Did - x coordinate>
   <Private point Did - y coordinate>

 */

#include <iostream>
#include <fstream>
#include <cstring>
#include "ecn.h"
#include "zzn.h"

using namespace std;

// Using SHA-1 as basic hash algorithm

#define HASH_LEN 20

//
// Hash function
// 

Big H1(char *string)
{ // Hash a zero-terminated string to a number < modulus
    Big h,p;
    char s[HASH_LEN];
    int i,j; 
    sha sh;

    shs_init(&sh);

    for (i=0;;i++)
    {
        if (string[i]==0) break;
        shs_process(&sh,string[i]);
    }
    shs_hash(&sh,s);

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

//
// MapToPoint
// Note deterministic mapping possible in this case
//

ECn map_to_point(char *ID)
{
    ECn Q;
    Big x0=H1(ID);
 
    if (is_on_curve(x0)) Q.set(x0);
    else                 Q.set(-x0);

    return Q;
}

int main()
{
    miracl *mip=mirsys(PBITS/MIRACL,0);     // thread-safe ready.  
    ifstream common("commonx.ibe");
    ifstream master("masterx.ibe");
    ofstream private_key("privatex.ibe");
    ECn Qid,Did;
    Big p,q,cof,s,x,y;
    int bits;

    common >> bits;
    mip->IOBASE=16;
    common >> p >> q;
    master >> s;
    mip->IOBASE=10;

    ecurve(-3,0,p,MR_PROJECTIVE);
    cof=(p+1)/q;

// EXTRACT

    char id[1000];

    cout << "Enter your email address (lower case)" << endl;
    cin.getline(id,1000);

    Qid=map_to_point(id);

    Did=s*Qid;

    cout << "Private key= " << Did << endl;

    Did.get(x,y);
    mip->IOBASE=16;

    private_key << x << endl;
    private_key << y << endl;

    return 0;
}

