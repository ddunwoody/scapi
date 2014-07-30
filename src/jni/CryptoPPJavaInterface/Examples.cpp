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

// windows includes
#include "StdAfx.h"

// stdlib includes
#include <string>
#include <time.h>

// java jni includes
#include "jni.h"

// cryptopp includes
#include "filters.h"
#include "rabin.h"
#include "rsa.h"
#include "osrng.h"
#include "ecp.h"
#include "asn.h"
#include "oids.h"

// local includes
#include "Examples.h"

using namespace std;
using namespace CryptoPP;



JNIEXPORT void JNICALL Java_JavaCryptopp_invokeThousandRSA
  (JNIEnv *, jobject)
{
	CryptoPP::RSAFunction rsaFunc;

	rsaFunc.Initialize(541 *523, 3);

	CryptoPP::Integer a;


//	clock_t start;

//	double diff;

//	start = std::clock();
	for(int i=0;i<10000;i++)
	{
		a = rsaFunc.ApplyFunction(200000 + i);
	}
	
//	diff = ( clock() - start ) / (double)CLOCKS_PER_SEC;

}

JNIEXPORT jdouble JNICALL Java_JavaCryptopp_invokeECC
(JNIEnv *, jobject)
{

	//create random number
	// Pseudo Random Number Generator
	AutoSeededRandomPool rng;

	//Integer *input = new Integer(rng, 220);


	//p-224
	Integer p("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001h");
	Integer a("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFEh");
	Integer b("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4h");
	Integer gx("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21h");
	Integer gy("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34h");


	//P-256
/*	Integer p("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFh");
	Integer a("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFCh");
	Integer b("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604Bh");
	Integer gx("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296h");
	Integer gy("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5h");

*/
	Integer n("210548457523399");

	ECP curve( p, a, b );
	
	ECP::Point g( gx, gy );

	clock_t start;

	double diff;
	start = clock();
	for(int i=0;i<22;i++){
		Integer input(rng, 220);
		curve.ScalarMultiply(g,input );
	}
	diff = ( clock() - start ) / (double)CLOCKS_PER_SEC;

	return diff;

}

 /*
 * Class:     JavaCryptopp
 * Method:    initInvertibleRSA
 * Signature: (II)J
 */
JNIEXPORT jlong JNICALL Java_JavaCryptopp_initInvertibleRSA
  (JNIEnv *, jobject, jint numOfBits, jint pubKeyBits)

{
	///////////////////////////////////////
	// Pseudo Random Number Generator
	AutoSeededRandomPool rng;

	InvertibleRSAFunction *invRSAFunc = new InvertibleRSAFunction();


	invRSAFunc->Initialize(rng,numOfBits,pubKeyBits);

	return (jlong)invRSAFunc;


}

JNIEXPORT jlong JNICALL Java_JavaCryptopp_createRandNumber
  (JNIEnv *, jobject, jint numOfBits)

{
	// Pseudo Random Number Generator
	AutoSeededRandomPool rng;

	Integer *input = new Integer(rng, numOfBits);

	return  (jlong)input;
}

/*
 * Class:     JavaCryptopp
 * Method:    applyRSAFunction
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_JavaCryptopp_applyRSAFunction
  (JNIEnv *, jobject, jlong rsaPtr, jlong rsaInput)
{
	((InvertibleRSAFunction *)rsaPtr)->ApplyFunction(*(Integer *)rsaInput);
}


/*
 * Class:     JavaCryptopp
 * Method:    invertRSAFunction
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_JavaCryptopp_invertRSAFunction
  (JNIEnv *, jobject, jlong rsaPtr, jlong rsaInput)
{
	AutoSeededRandomPool rng;
	((InvertibleRSAFunction *)rsaPtr)->CalculateInverse(rng, *(Integer *)rsaInput);
}




JNIEXPORT jstring JNICALL Java_JavaCryptopp_loadRabinName
  (JNIEnv *env, jobject)
{
	CryptoPP::Rabin rb;
	string ls = rb.StaticAlgorithmName();


	return env->NewStringUTF(ls.c_str());
}
