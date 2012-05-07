/*
   Boneh and Franklin IBE

   Compile with modules as specified below

   For MR_PAIRING_CP curve
   cl /O2 /GX ibe.cpp cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_MNT curve
   cl /O2 /GX ibe.cpp mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
	
   For MR_PAIRING_BN curve
   cl /O2 /GX ibe.cpp bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   cl /O2 /GX ibe.cpp kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   cl /O2 /GX ibe.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   Test program 
*/

#include <iostream>
#include <ctime>

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************

#include "pairing_3.h"

//
// Note that for this protocol the roles of G1 and G2 can be swapped if so desired
//

int main()
{   
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	miracl* mip=get_mip();

	Big s,r,sigma,c,M,V,W;
	G2 P,Ppub,U;
	G1 Alice,D,rA;
	time_t seed;

	time(&seed);
    irand((long)seed);

// common values
	pfc.random(P);
	pfc.precomp_for_mult(P);  // Note that P is a constant - so precompute!
	pfc.random(s);
	Ppub=pfc.mult(P,s);		  // will exploit precomputation on P
	pfc.precomp_for_pairing(Ppub); // W is a system-wide constant

//extract
	pfc.hash_and_map(Alice,(char *)"Alice"); // Alices public key
	D=pfc.mult(Alice,s);                     // Alice's private key

//encrypt to (U,V,W)
	mip->IOBASE=256;
	M=(char *)"message"; // to be encrypted to Alice
	cout << "Message to be encrypted=   " << M << endl;
	mip->IOBASE=16;
	pfc.rankey(sigma);
	pfc.start_hash();
	pfc.add_to_hash(sigma);
	pfc.add_to_hash(M);
	r=pfc.finish_hash_to_group();

	U=pfc.mult(P,r);                             // will exploit precomputation on P
	rA=pfc.mult(Alice,r);
	V=pfc.hash_to_aes_key(pfc.pairing(Ppub,rA)); // Use public key - will exploit precomputation on Ppub
	V=lxor(sigma,V);
	W=lxor(M,sigma);

//decrypt from (U,V,W)
	
	sigma=lxor(V,pfc.hash_to_aes_key(pfc.pairing(U,D))); // Use private key
	M=lxor(W,sigma);

	pfc.start_hash();
	pfc.add_to_hash(sigma);
	pfc.add_to_hash(M);
	r=pfc.finish_hash_to_group();
	if (U!=pfc.mult(P,r))
	{
		cout << "CIphertext rejected" << endl;
		return 0;
	}
	
	mip->IOBASE=256;
	cout << "Decrypted message=         " << M << endl;

    return 0;
}
