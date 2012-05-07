#include "StdAfx.h"
#include "EvaluationHashFunction.h"
#include "NTL/GF2X.h"
#include "NTL/GF2E.h"
#include "NTL/GF2XFactoring.h"



EvaluationHashFunction::EvaluationHashFunction(void)
{
	generateIrredPolynomial();
}


EvaluationHashFunction::~EvaluationHashFunction(void)
{
	delete key;
}

void EvaluationHashFunction::generateIrredPolynomial(void)
{
	// An irreducible polynomial to be used as the modulus
	GF2X p; 

	//generate the irreducible polynomial x^64+x^4+x^3+x+1 to work with 
	SetCoeff(p, 64);
	SetCoeff(p, 4);
	SetCoeff(p, 3);
	SetCoeff(p, 1);
	SetCoeff(p, 0);

	//init the field with the newly generated polynomial.
	GF2E::init(p);
}


void EvaluationHashFunction::generatePolynom(unsigned char *input, int len, GF2EX& polynom)
{
	
	//go over the input and generate the coefficients one by one
	for (int i=0; i<len/8;i++)
	{
		//create a temp coefficient to fill
		GF2E coefficient;

		//generate a field element that matches the related location in the input.
		generateFieldElement(input + (i*8), coefficient);
	
		//set the relevant coefficient to the polynomial
		SetCoeff(polynom, i, coefficient);
	}
		
	
}


void EvaluationHashFunction::generateFieldElement(unsigned char* inputByteElement, GF2E& outputElement)
{

	//first create a GF2X
	GF2X polynomialElement; 

	//translate the bytes into a GF2X element
	GF2XFromBytes(polynomialElement, inputByteElement, 8);

	
	//convert the GF2X to GF2E
	outputElement = to_GF2E(polynomialElement);
}


void EvaluationHashFunction::init(unsigned char *inputKey){

	key = new GF2E;

	//create the key from the char array of size 4
	generateFieldElement(inputKey, *key);
}


// Computing the evaluation function
void EvaluationHashFunction::computeFunction(unsigned char * input, int inOffset, int inLen, unsigned char * output, int outOffset)
{
	//we need to compute the function M(key)*key.
	//The polynomial M is generated from the input

	//prepare the field. Generate the irreducible element that also initializes the GF2E
	//generateIrredPolynomial();


	//generate the input as a polynomial. Generate M(x).
	//first create an instance of GF2EX
	GF2EX inputPolynom;
	generatePolynom(input, inLen, inputPolynom);

	//evaluate M(key).
	GF2E intermediateVal = eval(inputPolynom, *key);

	//compute M(key)*key
	GF2E result = intermediateVal * (*key);

	//translate the result back to char array and put it in the output field
	//the function rep returns the representation of GF2E as the related GF2X, it returns as read only.
	BytesFromGF2X(output,rep(result),8);


}
