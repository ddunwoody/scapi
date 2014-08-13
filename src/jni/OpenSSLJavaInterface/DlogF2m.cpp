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
#include "DlogF2m.h"
#include "DlogEC.h"
#include <openssl/ec.h>
#include <iostream>

using namespace std;

/* 
 * function createCurve		: Creates the F2m curve.
 * param pBytes				: Represents the irreducible polynomial - each bit represents a term in the polynomial x^m + x^k3 + x^k2 + x^k1 + 1.
 * param aBytes				: The parameter a of the curve equation, y^2 + x*y = x^3 + a*x^2 + b.
 * param bBytes				: The parameter b of the curve equation, y^2 + x*y = x^3 + a*x^2 + b.
 * return					: Pointer to the created curve.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogECF2m_createCurve
  (JNIEnv *env, jobject, jbyteArray pBytes, jbyteArray aBytes, jbyteArray bBytes){

	  BN_CTX *ctx;
	  EC_GROUP *curve;
	  BIGNUM *a, *b, *p;
	 
	  // Set up the BN_CTX.
	  if(NULL == (ctx = BN_CTX_new())) return 0;

	  // Set the values of the curve parameters.

	  //Create BN a.
	  jbyte* a_bytes  = (jbyte*) env->GetByteArrayElements(aBytes, 0); 	  
	  if(NULL == (a = BN_bin2bn((unsigned char*) a_bytes, env->GetArrayLength(aBytes), NULL))) {
			env ->ReleaseByteArrayElements(aBytes, (jbyte*) a_bytes, 0);
			BN_CTX_free(ctx);
			return 0;
	  }
	  env ->ReleaseByteArrayElements(aBytes, (jbyte*) a_bytes, 0);

	  //Create BN b.
	  jbyte* b_bytes  = (jbyte*) env->GetByteArrayElements(bBytes, 0);
	  if(NULL == (b = BN_bin2bn((unsigned char*)b_bytes, env->GetArrayLength(bBytes), NULL))) {
			BN_CTX_free(ctx);
		    BN_free(a);
			env ->ReleaseByteArrayElements(bBytes, (jbyte*) b_bytes, 0);
			return 0;
	  }
	  env ->ReleaseByteArrayElements(bBytes, (jbyte*) b_bytes, 0);

	  //Create BN p.
	  jbyte* p_bytes  = (jbyte*) env->GetByteArrayElements(pBytes, 0);
	  if(NULL == (p = BN_bin2bn((unsigned char*)p_bytes, env->GetArrayLength(pBytes), NULL))) {
			BN_CTX_free(ctx);
		    BN_free(a);
			BN_free(b);
			env ->ReleaseByteArrayElements(bBytes, (jbyte*) b_bytes, 0);
			return 0;
	  }
	  env ->ReleaseByteArrayElements(pBytes, (jbyte*) p_bytes, 0);

	  // Create the curve using a, b, p.
	  if(NULL == (curve = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
			BN_CTX_free(ctx);
		    BN_free(a);
			BN_free(b);
			BN_free(p);
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
 * function initCurve		: Initialize the F2m curve with generator, order and cofactor.
 * param dlog				: Pointer to the native Dlog object.
 * param generator			: Pointer to the generator point.
 * param qBytes				: Bytes of the group's order.
 * param cofactorBytes		: Bytes of the group cofactor.
 * return					: 1 if the initialization succedded; False, otherwise.
 */
JNIEXPORT jint JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogECF2m_initCurve
  (JNIEnv *env, jobject, jlong dlog, jlong generator, jbyteArray qBytes, jbyteArray cofactorBytes){
	  
	  //Convert the order and cofactor into BIGNUM objects.
	  BIGNUM *order, *cofactor;
	  jbyte* q_bytes  = (jbyte*) env->GetByteArrayElements(qBytes, 0);
	  if(NULL == (order = BN_bin2bn((unsigned char*)q_bytes, env->GetArrayLength(qBytes), NULL))) {
			env ->ReleaseByteArrayElements(qBytes, (jbyte*) q_bytes, 0);
			return 0;
	  }
	  env ->ReleaseByteArrayElements(qBytes, (jbyte*) q_bytes, 0);

	  jbyte* cofactor_bytes  = (jbyte*) env->GetByteArrayElements(cofactorBytes, 0);
	  if(NULL == (cofactor = BN_bin2bn((unsigned char*)cofactor_bytes, env->GetArrayLength(cofactorBytes), NULL))){
			BN_free(order);
		    env ->ReleaseByteArrayElements(cofactorBytes, (jbyte*) cofactor_bytes, 0);
			return 0;
	  }
	  env ->ReleaseByteArrayElements(cofactorBytes, (jbyte*) cofactor_bytes, 0);

	  // Set the generator, cofactor and the order.
	  if(1 != EC_GROUP_set_generator(((DlogEC*) dlog)->getCurve(), (EC_POINT*) generator, order, cofactor)){
		  BN_free(order);
		  BN_free(cofactor);
		  return 0;

	  }
	  //Release the allocated memory.
	  BN_free(order);
	  BN_free(cofactor);

	  return 1;
}

