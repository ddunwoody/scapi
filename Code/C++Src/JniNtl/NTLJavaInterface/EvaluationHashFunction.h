#pragma once
#include "NTL/GF2EX.h"
#include "NTL/GF2E.h"

NTL_CLIENT


/********************************************************************
	created:	2011/06/16
	created:	16:6:2011   14:27
	file base:	EvaluationHashFunction
	file ext:	h
	author:		LabTest
	
	purpose:	This class implements the Evaluation hash function with 64 bits.
				The class uses the NTL library to invoke GF(2^64) finite field operations.
				The field GF(2^64) is represented as GF(2)[x]/f(x), with f(x) = x64 + x4 + x3 + x + 1.  
				f(x) is a good 64 degree irreducible polynomial that will be fixed for all computations.
				The input m (of length < 64t bits) is viewed as a polynomial M(x) of degree < t over GF(264) as follows.
				Every 64 bits of m are viewed as an element in GF(2^64). Every such element is a coefficient of the polynom M(x). The total of at most 
				t coefficients give a polynom of degree at most t.

				The main function of this class is computeFunction. It does the following.
				COMPUTE M(a)*a in  GF(2^64)       [key=a, data= M(x)] as follows
				Evaluate the polynomial M(x) on a to get M(a) in GF(2^64) 
				Multiply by a in GF(2^64) to get M(a)*a in GF(2^64)       


*********************************************************************/
class EvaluationHashFunction
{
private:

	GF2E *key;

public:

	//constructor destructor
	EvaluationHashFunction(void);
	~EvaluationHashFunction(void);

	/*
	 *	
	 */
	void init(unsigned char *key);

	void generateIrredPolynomial(void);
	void generatePolynom(unsigned char *input, int len, GF2EX& polynom);
	void generateFieldElement(unsigned char* inputByteElement, GF2E& outputElement);
	
	// Computing the evaluation function
	void computeFunction(unsigned char * input, int inOffset, int inLen, unsigned char * output, int outOffset);
};

