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
#include <iostream>
#include <queue.h>

// cryptopp includes
#include "integer.h"

// local includes
#include "Utils.h"

using namespace std;

/* function Utils	: constructor
 * return			: 
 */
Utils::Utils() {}

/* function jbyteArrayToCryptoPPInteger : This function converting from jbyteArray to Integer
 * param env							: the jni pointer
 * param byteArrToInteger				: the byte array to convert
 * return								: the result
 */
Integer Utils::jbyteArrayToCryptoPPInteger (JNIEnv *env, jbyteArray byteArrToConvert) {

	jbyte* pjbyte;
	Integer result;
	
	//get jbyte* from byteArrToConvert
	pjbyte  = env -> GetByteArrayElements(byteArrToConvert, 0);

	//build the Integer 
	result = Integer((byte*)pjbyte, env->GetArrayLength(byteArrToConvert) , Integer::SIGNED);

	//release jbyte
	env ->ReleaseByteArrayElements(byteArrToConvert, pjbyte, 0);

	//return the Integer
	return result;
}

/* function jbyteArrayToCryptoPPIntegerPointer  : This function converting from jbyteArray to Integer and return pointer to the result integer
 * param env									: the jni pointer
 * param byteArrToInteger						: the byte array to convert
 * return										: the pointer to the Integer 
 */
Integer* Utils::jbyteArrayToCryptoPPIntegerPointer (JNIEnv *env, jbyteArray byteArrToConvert){
	//make new Integer from the jbyteArray, and get pointer to it
	Integer* returnInt = new Integer(jbyteArrayToCryptoPPInteger(env, byteArrToConvert));
	
	//return the pointer
	return returnInt;
}

/* function getIntegerPointer : This function return pointer to the accepted integer
 * param integerToPointer	  : the integer
 * return					  : the pointer to the integer
 */
Integer* Utils::getPointerToInteger (Integer integerToPointer) {

	//allocate memory
	Integer* returnInt = new Integer(integerToPointer);

	//return pointer to the result
	return returnInt;
}

/* function CryptoPPIntegerTojbyteArray : This function converting from Integer to jbyteArray
 * param env							: the jni pointer
 * param byteArrToInteger				: the Integer to convert
 * return								: the result jbyteArray
 */
jbyteArray Utils::CryptoPPIntegerTojbyteArray (JNIEnv *env, Integer integerToConvert) {
	
	/* The translation of BigInteger to byte[] sometimes result in 0/-1 at the first byte in the array.
	 * Converting that array to Integer and back to jbyteArray delete this first byte and cause problems with the 
	 * building of the new BigInteger from that jbyteArray.
	 * So, we add one more byte to the byteArray and the function Encode of Integer know how to do the padding to get the right byte Array.
	 */
	int size = integerToConvert.ByteCount()+1;
	
	byte* byteValue = new byte[size]; // allocate memory for the byte array

	//convert the Integer to byteArray
	integerToConvert.Encode(byteValue, size, Integer::SIGNED);

	//build jbyteArray from the byteArray
	jbyteArray result = env ->NewByteArray(size);
	env->SetByteArrayRegion(result, 0, size, (jbyte*)byteValue);
	
	 //free the memory
	free(byteValue);

	//return the jbyteArray
	return result;

}

/* function extendedEuclideanAlg : This function do the extendedEuclidean algorithm
 * param a						 : the bigger number between the two numbers
 * param b						 : the smaller number between the two numbers
 * param gcd					 : the GCD of the two numbers
 * param x						 : the result - coefficient of b
 * param y						 : the result - coefficient of a
 */
void Utils::extendedEuclideanAlg(Integer a, Integer b, Integer & gcd, Integer & x, Integer&  y) {
	x=0, y=1; 
    Integer u=1, v=0, m, n, q, r;
    gcd = a;
	//loop that return the right x,y
    while (b!=0) {
        q=gcd/b;
		r=gcd%b;
        m=x-u*q; 
		n=y-v*q;
        gcd=b; 
		b=r; 
		x=u; 
		y=v; 
		u=m; 
		v=n;
    }
}


/* function SquareRoot : This function return the square root of a value modulus mod
 * param value		   : the number to calculate its square root
 * param mod		   : modulus, such that mod = p*q
 * param p			   : prime 1, such that p=3mod4 and p*q = mod
 * param q			   : prime 2, such that q=3mod4 and p*q = mod
 */
Integer Utils::SquareRoot(Integer value, Integer mod, Integer p, Integer q, bool check=false) {
	Integer pMod4, qMod4;
	Integer vModP, vModQ;
	Integer srModP, srModQ;
	Integer xP, yQ, gcd;
	Integer pUnit, qUnit;
	Integer square;
	if (check){

		pMod4 = p.Modulo(4);
		qMod4 = q.Modulo(4);

		//if p or q is not 3mod4 return false (-1)
		if ((pMod4 != 3) || (qMod4 != 3)){
			return -1;
		}

		if (p*q != mod){
			return false;
		}

	}
	vModP = value.Modulo(p); //value mod(p)
	vModQ = value.Modulo(q); //value mod(q)
	
	srModP = a_exp_b_mod_c(vModP, ((p+1)/4), p); //square root of vModP
	srModQ = a_exp_b_mod_c(vModQ, ((q+1)/4), q); //square root of vModQ
	
	//calculate Xp, Yq
	if (p>q)
		extendedEuclideanAlg(p, q, gcd, yQ, xP);
	else
		extendedEuclideanAlg(q, p, gcd, xP, yQ);
	
	//calculate 1p, 1q
	pUnit = (yQ*q).Modulo(mod);
	qUnit = (xP*p).Modulo(mod);
	
	//calculate the square root
	square = ((srModP * pUnit) + (srModQ * qUnit)).Modulo(mod);
	return square; 
}

bool Utils::HasSquareRoot(Integer x, Integer p, Integer q){

	Integer xModP, xModQ;
	Integer srModP, srModQ;

	xModP = x.Modulo(p); //value mod(p)
	xModQ = x.Modulo(q); //value mod(q)
	
	srModP = a_exp_b_mod_c(xModP, ((p-1)/2), p); //square root of xModP
	srModQ = a_exp_b_mod_c(xModQ, ((q-1)/2), q); //square root of xModQ

	if ((srModP == 1) && (srModQ == 1)){
		return true;
	}else{
		return false;
	}

}
