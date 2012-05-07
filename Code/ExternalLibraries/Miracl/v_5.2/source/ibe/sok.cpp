/*
	Sakai, Ohgishi and Kasahara non-interactive ID based key exchange
	uses type 1 pairing

	Note that we understand that this method is patented.

	Compile with modules as specified below
	
	For MR_PAIRING_SS2 curves
	cl /O2 /GX sok.cpp ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.lib
  
	For MR_PAIRING_SSP curves
	cl /O2 /GX sok.cpp ssp_pair.cpp ecn.cpp zzn2.cpp zzn.cpp big.cpp miracl.lib

	Very Simple Test program 
*/

#include <iostream>
#include <ctime>

//********* choose just one of these **********
//#define MR_PAIRING_SS2    // AES-80 or AES-128 security GF(2^m) curve
//#define AES_SECURITY 80   // OR
//#define AES_SECURITY 128

#define MR_PAIRING_SSP    // AES-80 or AES-128 security GF(p) curve
//#define AES_SECURITY 80   // OR
#define AES_SECURITY 128
//*********************************************

#include "pairing_1.h"

int main()
{   
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve

	Big s,key;
	G1 Alice,Bob,sA,sB;
	GT K;
	time_t seed;

	time(&seed);
    irand((long)seed);

// setup
	pfc.random(s);

// extract private key for Alice
	pfc.hash_and_map(Alice,(char *)"Alice");
	sA=pfc.mult(Alice,s);

// extract private key for Bob
	pfc.hash_and_map(Bob,(char *)"Robert");
	sB=pfc.mult(Bob,s);

// Alice calculates mutual key

	K=pfc.pairing(sA,Bob);
	key=pfc.hash_to_aes_key(K);
	cout << "Alice's key= " << key << endl;

// Bob calculates mutual key
	K=pfc.pairing(sB,Alice);
	key=pfc.hash_to_aes_key(K);
	cout << "Bob's key=   " << key << endl;

    return 0;
}
