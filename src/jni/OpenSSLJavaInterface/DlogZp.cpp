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
#include "DlogZp.h"
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <iostream>

using namespace std;

/* 
 * function createDlogZp	: Creates the Zp* Dlog group.
 * param p					: Bytes of the group's safe prime.
 * param q					: Bytes of the group's order.
 * param g					: Bytes of the group's generator.
 * return					: Pointer to the created group.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_createDlogZp
  (JNIEnv *env, jobject, jbyteArray p, jbyteArray q, jbyteArray g){
	  DH * dh = DH_new();

	  //Convert the given data into c++ notation.
	  jbyte* pBytes  = (jbyte*) env->GetByteArrayElements(p, 0);
	  jbyte* qBytes  = (jbyte*) env->GetByteArrayElements(q, 0);
	  jbyte* generator  = (jbyte*) env->GetByteArrayElements(g, 0);

	  dh->p = BN_bin2bn((unsigned char*)pBytes, env->GetArrayLength(p), NULL);
	  dh->q = BN_bin2bn((unsigned char*)qBytes, env->GetArrayLength(q), NULL);
	  dh->g = BN_bin2bn((unsigned char*)generator, env->GetArrayLength(g), NULL);

	  env->ReleaseByteArrayElements(p, pBytes, 0);
	  env->ReleaseByteArrayElements(q, qBytes, 0);
	  env->ReleaseByteArrayElements(g, generator, 0); 

	  if ((dh->p == NULL) || (dh->q == NULL) ||(dh->g == NULL) ){
		  DH_free(dh);
		  return 0;
	  }
	  
	  // Set up the BN_CTX.
	  BN_CTX *ctx;
	  if(NULL == (ctx = BN_CTX_new())){
		  DH_free(dh);
		  return 0;
	  }

	  //Create a native Dlog object with dh and ctx.
	  DlogZp* dlog = new DlogZp(dh,  ctx);

	  return (long) dlog;
}

/* 
 * function createRandomDlogZp	: Creates a Zp* Dlog group with random values.
 * param numBits				: The requested number of bits that in the group's safe prime.
 * return						: Pointer to the created group.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_createRandomDlogZp
  (JNIEnv *, jobject, jint numBits){
	  
	  DH * dh = DH_new();

	  //Set up the BN_CTX.
	  BN_CTX *ctx;
	  if(NULL == (ctx = BN_CTX_new())){
		  DH_free(dh);
		  return 0;
	  }

	  //Seed the random geneartor.
#ifdef _WIN32
	  RAND_screen(); // only defined for windows, reseeds from screen contents
#else
	  RAND_poll(); // reseeds using hardware state (clock, interrupts, etc).
#endif
	  
	  //Sample a random safe prime with the requested number of bits.
	  dh->p = BN_new();
	  if(0 == (BN_generate_prime_ex(dh->p, numBits, 1, NULL, NULL, NULL))){
		  BN_CTX_free(ctx);
		  DH_free(dh);
		  return 0;
	  }
	  
	  //Calculates q from p, such that p = 2q + 1.
	  dh->q = BN_new();
	  if(0 == (BN_rshift1(dh->q,dh->p))){
		  BN_CTX_free(ctx);
		  DH_free(dh);
		  return 0;
	  }
	  
	  //Sample a generator to the group. 
	  //Each element in the group, except the identity, is a generator. 
	  //The elements in the group are elements that have a quadratic residue modulus p.
	  //Algorithm:
	  //	g <- 0
	  //	while g == 0 or g == 1:
	  //		Sample a number between 0 to p, set it to g
	  //		calculate g = g^2 nod p
	  dh->g = BN_new();
	  while(BN_is_zero(dh->g) || BN_is_one(dh->g)){
		  BN_rand_range(dh->g, dh->p);
		  BN_mod_sqr(dh->g, dh->g, dh->p, ctx);
	  }

	  //Create a native Dlog object with dh and ctx.
	  DlogZp* dlog = new DlogZp(dh,  ctx);
	  
	  return (long) dlog;
}

/* 
 * function getGenerator	: Returns the generator of the group.
 * return					: Pointer to the group's generator.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_getGenerator
  (JNIEnv *, jobject, jlong dlog){
	  
	  return (long) ((DlogZp*) dlog) -> getDlog() -> g;
}

/* 
 * function getP	: Returns the prime of the group.
 * return			: The bytes of the group's prime.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_getP
  (JNIEnv *env, jobject, jlong dlog){
	  //Get the prime.
	  BIGNUM* p = ((DlogZp*) dlog) -> getDlog() -> p;
	  char* elementBytes = new char[BN_num_bytes(p)];

	  //Convert the prime into byte array.
	  int len = BN_bn2bin(p, (unsigned char*)elementBytes);

	   //build jbyteArray from the byte array.
	  jbyteArray result = env ->NewByteArray(len);
	  env->SetByteArrayRegion(result, 0, len, (jbyte*)elementBytes);
	 
	  //Release the allocated memory.
	  delete elementBytes;

	  return result;
}

/* 
 * function getQ	: Returns the order of the group.
 * return			: The bytes of the group's order.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_getQ
  (JNIEnv *env, jobject, jlong dlog){
	  //Get the order.
	  BIGNUM* q = ((DlogZp*) dlog) -> getDlog() -> q;
	  char* elementBytes = new char[BN_num_bytes(q)];

	  //Convert the order into byte array.
	  int len = BN_bn2bin(q, (unsigned char*)elementBytes);

	  //build jbyteArray from the byte array.
	  jbyteArray result = env ->NewByteArray(len);
	  env->SetByteArrayRegion(result, 0, len, (jbyte*)elementBytes);

	   //Release the allocated memory.
	  delete elementBytes;

	  return result;
}

/* 
 * function inverseElement	: Returns the inverse of the given element.
 * param dlog				: Pointer to the native Dlog group.
 * param element			: That should be inverted.
 * return					: Pointer to the result's element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_inverseElement
  (JNIEnv *, jobject, jlong dlog, jlong element){
	  DH* dh = ((DlogZp*) dlog) -> getDlog();
	  
	  //Prepare a result element.
	  BIGNUM* result = BN_new();
	  //Invert the given element and put the result in result.
	  BN_mod_inverse(result, (BIGNUM*) element, dh->p, ((DlogZp*) dlog) ->getCTX());

	  return (long) result;
}

/* 
 * function exponentiateElement	: Raises the given base element to the given exponent.
 * param dlog					: Pointer to the native Dlog group.
 * param base					: That should be raised to the exponent.
 * param exponent
 * return						: Pointer to the result's element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_exponentiateElement
  (JNIEnv *env, jobject, jlong dlog, jlong base, jbyteArray exponent){
	  jbyte* exponent_bytes  = (jbyte*) env->GetByteArrayElements(exponent, 0);

	  DH* dh = ((DlogZp*) dlog) -> getDlog();
	  
	  //Convert the exponent into a BIGNUM object.
	  BIGNUM* expBN;
	  if(NULL == (expBN = BN_bin2bn((unsigned char*)exponent_bytes, env->GetArrayLength(exponent), NULL))){
		  env ->ReleaseByteArrayElements(exponent, (jbyte*) exponent_bytes, 0);
		  return 0;
	  }
	  env ->ReleaseByteArrayElements(exponent, (jbyte*) exponent_bytes, 0);

	  //Prepare a result element.
	  BIGNUM* result = BN_new();
	  //Raise the given element and put the result in result.
	  if(0 == (BN_mod_exp(result, (BIGNUM *) base, expBN, dh->p, ((DlogZp*) dlog) -> getCTX()))){
		  BN_free(expBN);
		  return 0;
	  }

	  //Release the allocated memory.
	  BN_free(expBN);
	  

	  return (long) result;
}

/* 
 * function multiplyElements	: Multiplies the given elements.
 * param dlog					: Pointer to the native Dlog group.
 * param element1				: The first element to the multiplication.
 * param element2				: The second element to the multiplication.
 * return						: Pointer to the result's element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_multiplyElements
  (JNIEnv *, jobject, jlong dlog, jlong element1, jlong element2){
	  DH* dh = ((DlogZp*) dlog) -> getDlog();
	  	 
	  //Prepare a result element.
	  BIGNUM* result = BN_new();
	  //Multiply the elements.
	  if(0 == (BN_mod_mul(result, (BIGNUM*) element1, (BIGNUM*) element2, dh->p, ((DlogZp*) dlog) -> getCTX()))) return 0;
	  

	  return (long) result;
}

/* 
 * function deleteDlogZp	: Deletes the group. Release the allocated memory.
 * param dlog				: Pointer to the native Dlog group.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_deleteDlogZp
  (JNIEnv *, jobject, jlong dlog){
	  delete (DlogZp*) dlog;
}

/* 
 * function validateZpGroup		: Checks if the given group is valid.
 * param dlog					: Pointer to the native Dlog group.
 * return						: True if the group is valid; False, otherwise.
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_validateZpGroup
  (JNIEnv *, jobject, jlong dlog){
	  int result; 
	  //Run a check of the group.
	  int suc = DH_check(((DlogZp*) dlog) -> getDlog(), &result);
	 
	  //In case the generator is 2, OpenSSL checks the prime is congruent to 11.
	  //while the IETF's primes are congruent to 23 when g = 2. Without the next check, the IETF parameters would fail validation.
	  if(BN_is_word(((DlogZp*) dlog) -> getDlog()->g, DH_GENERATOR_2))
	  {
		  long residue = BN_mod_word(((DlogZp*) dlog) -> getDlog()->p, 24);
		  if(residue == 11 || residue == 23) {
			  result &= ~DH_NOT_SUITABLE_GENERATOR;
		  }
	
	  }

	  //In case the generator is not 2 or 5, openssl does not check it and returns result == 4 in DH_check function.
	  //We check it directly.
	  if (result == 4){
		  BIGNUM* g = ((DlogZp*) dlog) -> getDlog() -> g;
		  result =  !((DlogZp*) dlog) -> validateElement((BIGNUM*) g);
	  }

	  if (result == 0){
		  return true;
	  }else {
		  return false;
	  }
}

/* 
 * function validateZpGenerator		: Checks if the generator of the given group is valid.
 * param dlog						: Pointer to the native Dlog group.
 * return							: True if the generator is valid; False, otherwise.
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_validateZpGenerator
  (JNIEnv *, jobject, jlong dlog){
	  
	  BIGNUM* g = ((DlogZp*) dlog) -> getDlog() -> g;
	  
	  //Call the function that checks an element's validity.
	  return ((DlogZp*) dlog) -> validateElement((BIGNUM*) g);
}

/* 
 * function validateZpElement		: Checks if the given element is a valid element in the given group.
 * param dlog						: Pointer to the native Dlog group.
 * params element					: to check.
 * return							: True if the element is valid; False, otherwise.
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLDlogZpSafePrime_validateZpElement
  (JNIEnv *, jobject, jlong dlog, jlong element){

	  return ((DlogZp*) dlog) -> validateElement((BIGNUM*) element);
}

/* 
 * function DlogZp		: Construct a Zp* dlog group.
 * param dh				: Pointer to a DH struct contains p, q, g.
 * params ctx			: Pointer to CTX struct.
 */
DlogZp::DlogZp(DH* dh, BN_CTX* ctx){

	this->dlog = dh;
	this->ctx = ctx;
}

/* 
 * function ~DlogZp		: Deletes a Zp* dlog group.
 */
DlogZp::~DlogZp(){
	//Release the allocated memory.
	BN_CTX_free(ctx);
	DH_free(dlog);
}

/* 
 * function getDlog		: Returns the pointer to the DH struct.
 */
DH* DlogZp::getDlog(){
	return dlog;
}

/* 
 * function getCTX		: Returns the pointer to the CTX struct.
 */
BN_CTX* DlogZp::getCTX(){
	return ctx;
}

/* 
 * function validateElement		: Checks if the given element is a valid element in the group.
 * params el					: Element to check.
 * return						: True if the element is valid; False, otherwise.
 */
bool DlogZp::validateElement(BIGNUM* el){
	
	//A valid element in the grou pshould satisfy the following:
	//	1. 0 < el < p.
	//	2. el ^ q = 1 mod p.
	bool result = true;
	BIGNUM* p = dlog -> p;

	//Check that the element is bigger than 0.
	BIGNUM* zero = BN_new();
	BN_zero(zero);
	if (BN_cmp(el, zero) <= 0 ){
		result = false;
	}
	
	//Check that the element is smaller than p.
	if (BN_cmp(el, p) > 0 ){
		result = false;
	}
	
	BIGNUM* q = dlog -> q;
	BIGNUM* exp = BN_new();
	
	//Check that the element raised to q is 1 mod p.
	int suc = BN_mod_exp(exp, el, q, p,  ctx);
	
	if (!BN_is_one(exp)){
		result = false;
	}
	
	//Release the allocated memory.
	BN_free(zero);
	BN_free(exp);

	return result;
}
