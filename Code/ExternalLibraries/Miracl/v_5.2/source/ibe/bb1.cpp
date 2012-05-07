/*
   Boneh and Boyen BB1 IBE
   See http://crypto.stanford.edu/~dabo/papers/bbibe.pdf
   Section 4.3

   Compile with modules as specified below

   For MR_PAIRING_CP curve
   cl /O2 /GX bb1.cpp cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_MNT curve
   cl /O2 /GX bb1.cpp mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
	
   For MR_PAIRING_BN curve
   cl /O2 /GX bb1.cpp bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   cl /O2 /GX bb1.cpp kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   cl /O2 /GX bb1.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   Test program 
*/

#include <iostream>
#include <ctime>

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

#define MR_PAIRING_MNT	// AES-80 security
#define AES_SECURITY 80

//#define MR_PAIRING_BN    // AES-128 or AES-192 security
//#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************

#include "pairing_3.h"

//
// Observe that every major operation benefits from precomputation!
//

int main()
{   
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
    miracl* mip=get_mip();
	Big order=pfc.order();

	Big alpha,delta,beta,a,r,s,c1,M;
	G2 ghat,da0,da1;
	G1 g,gone,h,c2,c3;
	GT v;
	int lsb;
	time_t seed;

	time(&seed);
    irand((long)seed);

// common values

	pfc.random(alpha);
	pfc.random(g);
	gone=pfc.mult(g,alpha);
	pfc.random(ghat);
	pfc.random(delta);
	h=pfc.mult(g,delta);
	pfc.random(beta);
	v=pfc.power(pfc.pairing(ghat,g),modmult(alpha,beta,order));
	cout << "Precomputation" << endl;
	pfc.precomp_for_power(v);   // precomputation
	pfc.precomp_for_mult(g);
	pfc.precomp_for_mult(h);
	pfc.precomp_for_mult(gone);
	pfc.precomp_for_mult(ghat);  // master key is {ghat,alpha,beta,delta}


//extract
	cout << "Private key extraction" << endl;
	a=pfc.hash_to_group((char *)"Alice");
	pfc.random(r);
	da0=pfc.mult(ghat,(modmult(alpha,beta,order)+modmult(modmult(alpha,a,order)+delta,r,order))%order);
	da1=pfc.mult(ghat,r);	da1=-da1;
	pfc.precomp_for_pairing(da0);  // Alice precomputes on her private key !
	pfc.precomp_for_pairing(da1);

//encrypt
	cout << "Encryption" << endl;
	mip->IOBASE=256;
	M=(char *)"a message"; // to be encrypted to Alice
	cout << "Message to be encrypted=   " << M << endl;
	mip->IOBASE=16;
	pfc.random(s);

	c1=lxor(M,pfc.hash_to_aes_key(pfc.power(v,s)));
	c2=pfc.mult(g,s);
	c3=pfc.mult(h,s)+pfc.mult(gone,modmult(a,s,order));

//decrypt

	G1 *g1[2];
	G2 *g2[2];
	g1[0]=&c2; g1[1]=&c3;
	g2[0]=&da0; g2[1]=&da1;

	M=lxor(c1,pfc.hash_to_aes_key(pfc.multi_pairing(2,g2,g1)));	// Use private key
	mip->IOBASE=256;
	cout << "Decrypted message=         " << M << endl;

    return 0;
}
