/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/

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

