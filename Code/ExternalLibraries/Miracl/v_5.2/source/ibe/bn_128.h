/*
 *    No matter where you got this code from, be aware that MIRACL is NOT 
 *    free software. For commercial use a license is required.
 *	  See www.shamus.ie
 *
 * bn_128.h
 *
 * BN curve, ate pairing embedding degree 12, security level AES-128
 *
 * Requires: bn_128.cpp zzn12a.cpp zzn4.cpp ecn2.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.a
 * 
 *  Irreducible poly is X^3+n, where n=sqrt(w+sqrt(m)), m= {-1,-2} and w= {0,1,2}
 *         if p=5 mod 8, n=sqrt(-2)
 *         if p=3 mod 8, n=1+sqrt(-1)
 *         if p=7 mod 8, p=2,3 mod 5, n=2+sqrt(-1)
 *
 *  See bn.cpp for a program to generate suitable BN curves
 *
 * High level interface to pairing functions
 * 
 * GT=pairing(G1,G2)
 *
 * This is calculated on a Pairing Friendly Curve (PFC), which must first be defined.
 *
 * G1 is a point over the base field, and G2 is a point over the extension field of degree 2
 * GT is a finite field point over the 12-th extension, where 12 is the embedding degree.
 *
 */

#include "ecn2.h"   // G1
#include "ecn.h"	// G2
#include "zzn12a.h" // GT

#define ATE_PAIRING  
#define WINDOW_SIZE 8 // window size for precomputation
#define EXP_BITS 256  // max exponent size in bits
#define MOD_BITS 256  // modulus size in bits

class PFC;
extern void read_only_error(void);

// Multiples of G2 may be precomputed. If it is, the instance becomes read-only.
// Read-only instances cannot be written to - causes an error and exits
// Precomputation for pairing calculation only possible for G1 for Tate pairing, and G2 for ate pairing

class G1
{
public:
	ECn g;


	ECn *mtable;   // pointer to values precomputed for multiplication
 
    G1()   {mtable=NULL;}
	G1(const G1& w) {mtable=NULL; g=w.g;}

	G1& operator=(const G1& w) 
	{
		if (mtable==NULL) g=w.g; 
		else read_only_error();
		return *this;
	} 

	~G1()  {if (mtable!=NULL) {delete [] mtable; mtable=NULL;}}
};

//
// This is just an ECn2. But we want to restrict the ways in which it can be used. 
// We want the instances to always be of an order compatible with the PFC
//

class G2
{
public:
	ECn2 g;

	ZZn2 *ptable;  // pointer to values precomputed for pairing
	ECn2 *mtable;  // pointer to values precomputed for multiplication

    G2()   {ptable=NULL; mtable=NULL;}
	G2(const G2& w) {ptable=NULL; mtable=NULL; g=w.g;}
	G2& operator=(const G2& w) 
	{ 
		if (ptable==NULL && mtable==NULL)	g=w.g; 
		else read_only_error(); 
		return *this; 
	} 
	~G2()	{if (mtable!=NULL) {delete [] mtable; mtable=NULL;}
			 if (ptable!=NULL) {delete [] ptable; ptable=NULL;}}
};

class GT
{
public:
	ZZn6 g;

	ZZn6 *etable;

	GT() {etable=NULL;}
	GT(const GT& w) {etable=NULL; g=w.g;}
	GT(int d) {etable=NULL; g=d;}

	GT& operator*=(const GT& w) 
	{
		if (etable==NULL) g*=w.g;
		else read_only_error();
		return *this;
	}
	GT& operator=(const GT& w)  
	{
		if (etable==NULL) g=w.g; 
		else read_only_error(); 
		return *this;
	} 
	friend GT operator*(const GT&,const GT&);
	friend BOOL operator==(const GT& x,const GT& y)
      {if (x.g==y.g) return TRUE; else return FALSE; }
	~GT() {if (etable!=NULL) {delete [] etable; etable=NULL;}}
};

// pairing friendly curve class

class PFC
{
	Big A,B;
public:
	Big x;       // curve parameter
	Big modulus;
	Big order;
	Big cofactor; //cofactor = npoints/order
	Big npoints;  
	Big trace;
	Big BB[4][4],WB[4],SB[2][2],W[2];
	ZZn beta;
	ZZn2 frob;    // Frobenius constant
	PFC(const Big&,const Big&,const Big&);
	GT power(const GT&,const Big&);  
	G1 mult(const G1&,const Big&);
	G2 mult(const G2&,const Big&);
	G1 G1_hash_and_map(char *);
	G2 G2_hash_and_map(char *);
	BOOL member(const GT&);			// test if element is member of pairing friendly group
	void precomp_for_pairing(G1&);  // precompute multiples of G1 that occur in Miller loop
	void precomp_for_mult(G1&);     // precompute multiples of G1 for precomputation
	void precomp_for_mult(G2&);
	void precomp_for_power(GT&);
	GT miller_loop(const G1&,const G2&);
	GT final_exp(const GT&);
	GT pairing(const G1&,const G2&);
// parameters: number of pairings n, pointers to G1 and G2 elements
	GT multi_miller(int n,G1 **,G2 **);
	GT multi_pairing(int n,G1 **,G2 **); //product of pairings
};

extern Big Hash(const GT&);

#if MOD_BITS%MIRACL==0
#define WORDS MOD_BITS/MIRACL
#else
#define WORDS (MODBITS/MIRACL)+1
#endif
