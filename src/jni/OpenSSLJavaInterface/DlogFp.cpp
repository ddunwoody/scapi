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

#include "StdAfx.h"
#include <jni.h>
#include "DlogFp.h"
#include "DlogEC.h"
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <cstring>	// For memcpy
#include <iostream>

using namespace std;

/* 
 * function createCurve		: Creates the Fp curve.
 * param pBytes				: Bytes of the group's modulus.
 * param aBytes				: The parameter a of the curve equation, y^2 + x*y = x^3 + a*x^2 + b.
 * param bBytes				: The parameter b of the curve equation, y^2 + x*y = x^3 + a*x^2 + b.
 * return					: Pointer to the created curve.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogECFp_createCurve
  (JNIEnv *env, jobject, jbyteArray pBytes, jbyteArray aBytes, jbyteArray bBytes){

	  BN_CTX *ctx;
	  EC_GROUP *curve;
	  BIGNUM *a, *b, *p;
	 
	  //Convert the jbyteArrays to c++ notation.
	  jbyte* p_bytes  = (jbyte*) env->GetByteArrayElements(pBytes, 0);
	  if(NULL == (p = BN_bin2bn((unsigned char*)p_bytes, env->GetArrayLength(pBytes), NULL))){
		  env ->ReleaseByteArrayElements(pBytes, (jbyte*) p_bytes, 0);
		  return 0;
	  }
	  env ->ReleaseByteArrayElements(pBytes, (jbyte*) p_bytes, 0);

	  jbyte* a_bytes  = (jbyte*) env->GetByteArrayElements(aBytes, 0);
	  if(NULL == (a = BN_bin2bn((unsigned char*) a_bytes, env->GetArrayLength(aBytes), NULL))){
		  BN_free(p);
		  env ->ReleaseByteArrayElements(aBytes, (jbyte*) a_bytes, 0);
		  return 0;
	  }
	  env ->ReleaseByteArrayElements(aBytes, (jbyte*) a_bytes, 0);

	  jbyte* b_bytes  = (jbyte*) env->GetByteArrayElements(bBytes, 0);
	  if(NULL == (b = BN_bin2bn((unsigned char*)b_bytes, env->GetArrayLength(bBytes), NULL))){
		  BN_free(p);
		  BN_free(a);
		  env ->ReleaseByteArrayElements(bBytes, (jbyte*) b_bytes, 0);
		  return 0;
	  }
	  env ->ReleaseByteArrayElements(bBytes, (jbyte*) b_bytes, 0);

	  // Set up the BN_CTX.
	  if(NULL == (ctx = BN_CTX_new())){
		  BN_free(p);
		  BN_free(b);
		  BN_free(a);
		  return 0;
	  }

	  // Create the curve.
	  if(NULL == (curve = EC_GROUP_new_curve_GFp(p, a, b, ctx))){
		  BN_free(p);
		  BN_free(b);
		  BN_free(a);
		  BN_CTX_free(ctx);
		  return 0;

	  }
	  //Release the allocated memory.
	  BN_free(p);
	  BN_free(b);
	  BN_free(a);
	  
	  //Create Dlog group with the curve and ctx.
	  DlogEC* dlog = new DlogEC(curve, ctx);
	  return (long) dlog;
}

/* 
 * function initCurve		: Initialize the Fp curve with generator and order.
 * param dlog				: Pointer to the native Dlog object.
 * param generator			: Pointer to the generator point.
 * param qBytes				: Bytes of the group's order.
 * return					: 1 if the initialization succedded; False, otherwise.
 */
JNIEXPORT jint JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogECFp_initCurve
  (JNIEnv *env, jobject, jlong dlog, jlong generator, jbyteArray qBytes){
	  
	  //Convert the order into BIGNUM object.
	  BIGNUM *order;
	  jbyte* q_bytes  = (jbyte*) env->GetByteArrayElements(qBytes, 0);

	  if(NULL == (order = BN_bin2bn((unsigned char*)q_bytes, env->GetArrayLength(qBytes), NULL))){
		  env ->ReleaseByteArrayElements(qBytes, (jbyte*) q_bytes, 0);
		  return 0;
	  }
	  env ->ReleaseByteArrayElements(qBytes, (jbyte*) q_bytes, 0);

	  // Set the generator and the order.
	  if(1 != EC_GROUP_set_generator(((DlogEC*) dlog)->getCurve(), (EC_POINT*) generator, order, NULL)){
		  BN_free(order); 
		  return 0;
	  }
	
	  //Release the allocated memory.
	  BN_free(order);
	  
	  return 1;
}

/* 
 * function encodeByteArrayToPoint		: Encodes the given byte array into a point. 
 *										  If the given byte array can not be encoded to a point, returns 0.
 * param dlog							: Pointer to the native Dlog object.
 * param binaryString					: The byte array to encode.
 * param k								: k is the maximum length of a string to be converted to a Group Element of this group. 
 *										  If a string exceeds the k length it cannot be converted.
 * return								: The created point or 0 if the point cannot be created.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogECFp_encodeByteArrayToPoint
  (JNIEnv *env, jobject, jlong dlog, jbyteArray binaryString, jint k){
	 //Pseudo-code:
		/*If the length of binaryString exceeds k then throw IndexOutOfBoundsException.

          Let L be the length in bytes of p

          Choose a random byte array r of length L – k – 2 bytes 

          Prepare a string newString of the following form: r || binaryString || binaryString.length (where || denotes concatenation) (i.e., the least significant byte of newString is the length of binaryString in bytes)

          Convert the result to a BigInteger (bIString)

          Compute the elliptic curve equation for this x and see if there exists a y such that (x,y) satisfies the equation.

          If yes, return (x,y)

          Else, go back to step 3 (choose a random r etc.) up to 80 times (This is an arbitrary hard-coded number).

          If did not find y such that (x,y) satisfies the equation after 80 trials then return null.
		 */

	jbyte* string  = (jbyte*) env->GetByteArrayElements(binaryString, 0);
	int len = env->GetArrayLength(binaryString);

	EC_GROUP* curve = ((DlogEC*) dlog)->getCurve();

	if (len > k){
		env ->ReleaseByteArrayElements(binaryString, string, 0);
		return 0;
	}
	
	BIGNUM *x, *y, *p, *a, *b;
	x = BN_new();
	y = BN_new();
	a = BN_new();
	b = BN_new();
	p = BN_new();
	if (0 == (EC_GROUP_get_curve_GFp(curve, p, a, b, ((DlogEC*) dlog)->getCTX()))){
		env ->ReleaseByteArrayElements(binaryString, string, 0);
		BN_free(a);
		BN_free(b);
		BN_free(p);
		BN_free(x);
		BN_free(y);
	}

	BN_free(a);
	BN_free(b);
	int l = BN_num_bytes(p);

	jbyte* randomArray = new jbyte[l-k-2];
		
	jbyte* newString = new jbyte[l - k - 1 + len];
	memcpy(newString+l-k-2, string, len);
	newString[l - k - 2 + len] = (char) len;

	//Create an inverse point and copy the given point to it.
	EC_POINT *point;
	if(NULL == (point = EC_POINT_new(curve))){
		env ->ReleaseByteArrayElements(binaryString, string, 0);
		BN_free(p);
		BN_free(x);
		BN_free(y);
		delete(randomArray);
		delete(newString);
		return 0;
	}

	int counter = 0;
	bool success = 0;
	do{
			RAND_bytes((unsigned char*) randomArray, l-k-2);
			memcpy(newString, randomArray, l-k-2);
			
			//Convert the result to a BigInteger (bIString)
			if(NULL == (x = BN_bin2bn((unsigned char*)newString, l - k - 1 + len, NULL))) break;

			int numBytes = BN_num_bytes(x);
			//If the nmber is negative, make it positive.
			if(BN_is_bit_set(x, numBytes*8)){	
				BN_set_bit(x, numBytes*8);
			}

			//Try to create a point aith the generated x value.
			//if failed, go back to choose a random r etc.
			success = EC_POINT_set_compressed_coordinates_GFp(curve, point, x, 0, ((DlogEC*) dlog)->getCTX());
			counter++;
	} while((!success) && (counter <= 80)); //we limit the amount of times we try to 80 which is an arbitrary number.

	//Delete the allocated memory.
	env ->ReleaseByteArrayElements(binaryString, string, 0);
	BN_free(x);
	BN_free(y);
	BN_free(p);
	delete(randomArray);
	delete(newString);

	//If a point could not be created, return 0;
	if (!success){
		EC_POINT_free(point);
		return 0;
	}

	//Return the created point.
	return (long) point;
}

