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
#include "DlogEC.h"
#include <openssl/ec.h>
#include <iostream>

using namespace std;

/* 
 * function createInfinityPoint		: Creates an infinity point.
 * param dlog						: Pointer to the dlog group.
 * return							: A pointer to the created infinity point.
 */
JNIEXPORT jlong JNICALL JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_createInfinityPoint
  (JNIEnv *env , jobject, jlong dlog){

	  //Call the function in the Dlog group that perform the creation of infinity point.
	  return (long) ((DlogEC*)dlog)->createInfinityPoint();
}

/* 
 * function inversePoint		: Return the inverse of the given point.
 * param dlog					: Pointer to the dlog group.
 * param point					: The point that needs to be inverted.
 * return						: A pointer to the inverse point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_inversePoint
  (JNIEnv *env, jobject, jlong dlog, jlong point){
	  
	  //Call the function in the Dlog group that inverts the point.
	  return (long)((DlogEC*)dlog)->inversePoint((EC_POINT*)point);
	  
}

/* 
 * function exponentiate		: Raise the given base to the exponent.
 * param dlog					: Pointer to the dlog group.
 * param base					: The point that needs to be raised.
 * params exponent				: The number that the base point shoult be raised to.
 * return						: A pointer to the exponentiate result.
 */
JNIEXPORT jlong JNICALL JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_exponentiate
  (JNIEnv *env, jobject, jlong dlog, jlong base, jbyteArray exponentBytes){
	  //Convert the exponent to BIGNUM.
	  BIGNUM *exponent;
	  jbyte* exponent_bytes  = (jbyte*) env->GetByteArrayElements(exponentBytes, 0);
	  if(NULL == (exponent = BN_bin2bn((unsigned char*)exponent_bytes, env->GetArrayLength(exponentBytes), NULL))){
		  env ->ReleaseByteArrayElements(exponentBytes, (jbyte*) exponent_bytes, 0);
		  return 0;
	  }
	  env ->ReleaseByteArrayElements(exponentBytes, (jbyte*) exponent_bytes, 0);

	  EC_POINT *result;
	  //Call the function in the Dlog group that exponentiates the base to the exponent
	  if(0 == (result = ((DlogEC*)dlog)->exponentiate((EC_POINT*)base, exponent))){
		  BN_free(exponent);
		  return 0;
	  }
	  
	  //Release the allocated memory.
	  BN_free(exponent);
	  
	  return (long) result; //return the result
}

/* 
 * function multiply		: Multiplies the given points.
 * param dlog				: Pointer to the dlog group.
 * param point1				: The first point to multiply.
 * params point2			: The second point to multiply.
 * return					: A pointer to the multiply result.
 */
JNIEXPORT jlong JNICALL JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_multiply
  (JNIEnv *, jobject, jlong dlog, jlong point1, jlong point2){
	  
	  //Call the function in the Dlog group that multiplies the points.
	  return (long) ((DlogEC*)dlog)->multiply((EC_POINT*)point1, (EC_POINT*)point2); //return the result
}

/* 
 * function checkCurveMembership		: checks that the given oint is on the curve.
 * param dlog							: Pointer to the dlog group.
 * param point							: The point to check.
 * return								: True if the point is on the curve; False, otherwise.
 */
JNIEXPORT jboolean JNICALL JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_checkCurveMembership
  (JNIEnv *, jobject, jlong dlog, jlong point){
	  //Call the function in the Dlog group that checks membership.
	  return ((DlogEC*)dlog)->checkCurveMembership((EC_POINT*)point);
}

/* 
 * function simultaneousMultiply		: Computes the product of several exponentiations with distinct bases.
 * param dlog							: Pointer to the dlog group.
 * param points							: Array of points.
 * params exponents						: Array of exponents.
 * return								: Pointer to the result's point.
 */
JNIEXPORT jlong JNICALL JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_simultaneousMultiply
  (JNIEnv *env, jobject, jlong dlog, jlongArray points, jobjectArray exponents){
	
	  int size = env->GetArrayLength(points); //Number of points.
	  jlong* pointsArr  = env->GetLongArrayElements(points, 0); //Convert JllongArray to long array. 
	  BIGNUM ** exponentsArr =  new BIGNUM*[size]; //Create an array to hold the exponents.
	  int i;
	  
	  jbyteArray exponentBytes;
	  //Convert each exponent bytes to a BIGNUM object.
	  for(i=0; i<size; i++){
		  //Get the exponent bytes.
		  exponentBytes = (jbyteArray) env->GetObjectArrayElement(exponents, i);
		  jbyte* exponent_bytes  = (jbyte*) env->GetByteArrayElements(exponentBytes, 0);
		  //Convert to BIGNUM.
		  if(NULL == (exponentsArr[i] = BN_bin2bn((unsigned char*)exponent_bytes, env->GetArrayLength(exponentBytes), NULL))){
			  //release the memory
			  for(int j=0; j<i; j++){
				   BN_free(exponentsArr[j]);
			  }
			  env ->ReleaseByteArrayElements(exponentBytes, exponent_bytes, 0);
			  env ->ReleaseLongArrayElements(points, pointsArr, 0);
			  delete(exponentsArr);
			  return 0;

		  }
		  //Release the memory.
		  env ->ReleaseByteArrayElements(exponentBytes, exponent_bytes, 0);
	  }

	  //Call the function in the Dlog group that computes the simultaneous multiply.
	  EC_POINT *result = ((DlogEC*)dlog)->simultaneousMultiply((const EC_POINT**) pointsArr, (const BIGNUM **) exponentsArr, size);
	  
	  //release the memory
	  for(i=0; i<size; i++){
		   BN_free(exponentsArr[i]);
	  }
	  delete(exponentsArr);
	  env ->ReleaseLongArrayElements(points, pointsArr, 0);
	  
	  return (long) result;
}

/* 
 * function validate		: Validates the Dlog group
 * param dlog				: Pointer to the dlog group.
 * return					: True if the group is valid; False, otherwise.
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_validate
  (JNIEnv *, jobject, jlong dlog){
	  //Call the function in the Dlog group that validate the curve.
	  return ((DlogEC*)dlog)->validate();
}

/* 
 * function exponentiateWithPreComputedValues	: Exponentiates the generator to the given exponent using a pre computed values.
 * param dlog									: Pointer to the dlog group.
 * params exponentBytes							: The exponent.
 * return										: Pointer to the result's point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_exponentiateWithPreComputedValues
  (JNIEnv *env, jobject, jlong dlog, jbyteArray exponentBytes){
	  //Create the exponent BIGNUM.
	  BIGNUM *exponent;
	  jbyte* exponent_bytes  = (jbyte*) env->GetByteArrayElements(exponentBytes, 0);
	  if(NULL == (exponent = BN_bin2bn((unsigned char*)exponent_bytes, env->GetArrayLength(exponentBytes), NULL))) {
		  env ->ReleaseByteArrayElements(exponentBytes, (jbyte*) exponent_bytes, 0);
		  return 0;
	  }
	  //Release the allocated memory.
	  env ->ReleaseByteArrayElements(exponentBytes, (jbyte*) exponent_bytes, 0);

	  //Call the function in the Dlog group that computes the exponentiate with the pre computes values.
	  EC_POINT *result = ((DlogEC*)dlog)->exponentiateWithPreComputedValues(exponent);
	  
	  BN_free(exponent);
	  
	  return (long) result; //return the result
}

/* 
 * function deleteDlog			: Deletes the allocated memory.
 * param dlog					: Pointer to the dlog group.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_openSSL_OpenSSLAdapterDlogEC_deleteDlog
  (JNIEnv *, jobject, jlong dlog){
	  delete((DlogEC*)dlog);
}

/* 
 * function DlogEC				: Constructor that sets the curve and ctx.
 * param curveP					: Pointer to the curve.
 * params ctx					: Pointer to CTX struct.
 */
DlogEC::DlogEC(EC_GROUP* curveP, BN_CTX* ctx){

	this->curveP = curveP;
	this->ctx = ctx;
}

/* 
 * function ~DlogEC		: destructor
 */
DlogEC::~DlogEC(){
	BN_CTX_free(ctx);
	EC_GROUP_free(curveP);
}

/* 
 * function getCurve		: Returns the curve
 * return					: The curve.
 */
EC_GROUP* DlogEC::getCurve(){
	return curveP;
}

/* 
 * function getCTX		: Returns the CTX structure.
 * return				: ctx.
 */
BN_CTX* DlogEC::getCTX(){
	return ctx;
}

/* 
 * function createInfinityPoint			: Creates an infinity point.
 * return								: Pointer to the created infinity point.
 */
EC_POINT* DlogEC::createInfinityPoint(){
	//Declare a pointer to a point.
	EC_POINT *point;  

	//Create the pointer to a point.
	if(NULL == (point = EC_POINT_new(curveP))) return 0;

	//Set the point to be the infinity.
	if(0 == (EC_POINT_set_to_infinity(curveP, point))){
		EC_POINT_free(point);
		return 0;
	}
	
	return point;
}

/* 
 * function inversePoint			: Invert the given point.
 * param point						: Point that should be inverted.
 * return							: Pointer to the result's point.
 */
EC_POINT* DlogEC::inversePoint(EC_POINT* point){

	//Create an inverse point and copy the given point to it.
	EC_POINT *inverse;
	if(NULL == (inverse = EC_POINT_new(curveP))) return 0;
	if(0 == (EC_POINT_copy(inverse, point))) {
		EC_POINT_free(inverse);
		return 0;
	}

	//Inverse the given value and set the inversed value instead.
	if(0 == (EC_POINT_invert(curveP,  inverse, ctx))){
		EC_POINT_free(inverse);
		return 0;
	}
		
	return  inverse;
}

/* 
 * function exponentiate			: Raise the given base to the given exponent.
 * param base						: The point that should be raised.
 * param exponent					: 
 * return							: Pointer to the result's point.
 */
EC_POINT* DlogEC::exponentiate(EC_POINT* base, BIGNUM* exponent){
	//Prepare a point that will contain the exponentiate result.
	EC_POINT *result;
	if(NULL == (result = EC_POINT_new(curveP))) return 0;

	//Compute the exponentiate.
	if(0 == (EC_POINT_mul(curveP, result, NULL, base, exponent, ctx))) {
		EC_POINT_free(result);
		return 0;
	}

	return result;
}
	
/* 
 * function multiply			: Raise the given base to the given exponent.
 * param point1					: The first point to multiply.
 * param point2					: The second point to multiply.
 * return						: Pointer to the result's point.
 */
EC_POINT* DlogEC::multiply(EC_POINT* point1, EC_POINT* point2){
	//Prepare a point that will contain the multiplication result.
	EC_POINT *result;
	if(NULL == (result = EC_POINT_new(curveP))) return 0;

	//Compute the multiplication.
	if(0 == (EC_POINT_add(curveP, result, point1, point2, ctx))){
		EC_POINT_free(result);
		return 0;
	}

	return result; //return the result
}

/* 
 * function checkCurveMembership		: Checks if the given point is on the curve.
 * param point							: The point to check.
 * return								: True if the point is on the curve; False, otherwise.
 */
BOOL DlogEC::checkCurveMembership(EC_POINT* point){

	//Call the function that checks membership.
	int result = EC_POINT_is_on_curve(curveP, point, ctx);

	return result;
}

/* 
 * function simultaneousMultiply		: Computes the product of several exponentiations with distinct bases.
 * param pointsArr						: Bases array.
 * param exponentArr					: exponents array.
 * return								: The result's point.
 */
EC_POINT* DlogEC::simultaneousMultiply(const EC_POINT** pointsArr, const BIGNUM** exponentsArr, int size){
	//Prepare a point that will contain the multiplication result.
	EC_POINT *result;
	if(NULL == (result = EC_POINT_new(curveP))) return 0;

	//Computes the simultaneous multiply.
	if(0 == (EC_POINTs_mul(curveP, result, NULL, size, pointsArr, exponentsArr, ctx))){
		EC_POINT_free(result);
		return 0;
	}

	return result;

}
	
/* 
 * function validate		: checks that the current group is valid.
 * return					: True if the group is valid; False, otherwise.
 */
BOOL DlogEC::validate(){
	return EC_GROUP_check(curveP, ctx);
}

/* 
 * function exponentiateWithPreComputedValues		: Raises the generator to the given exponent.
 * param exponent									
 * return											: The result's point.
 */
EC_POINT* DlogEC::exponentiateWithPreComputedValues(BIGNUM* exponent){
	//Prepare a point that will contain the exponentiate result.
	EC_POINT *result;
	if(NULL == (result = EC_POINT_new(curveP))) return 0;

	//If there are no pre computes values, calculate them.
	if (EC_GROUP_have_precompute_mult(curveP) == 0){
		if(0 == (EC_GROUP_precompute_mult(curveP, ctx))) {
			EC_POINT_free(result);
			return 0;
		}
	}

	//Calculate the exponentiate with the pre computed values.
	if(0 == (EC_POINT_mul(curveP, result, exponent, NULL, NULL, ctx))){
		EC_POINT_free(result);
		return 0;
	}
	
	return result;

}
