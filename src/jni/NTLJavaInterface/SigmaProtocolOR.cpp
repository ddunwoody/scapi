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

#include "stdafx.h"
#include "EvaluationHashFunction.h"
#include "SigmaProtocolOR.h"
#include "NTL/GF2X.h"
#include "NTL/GF2E.h"
#include "NTL/GF2XFactoring.h"
#include "NTL/vec_GF2E.h"
#include "NTL/GF2EX.h"
#include "NTL/ZZ.h"

/* function initField : Initialize the field GF2E with irreducible polynomial.
	This function is used by the prover.
 * param t			  : degree of the irreducible polynomial
 * param randomNum	  : seed for the random calculations.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleProverComputation_initField
  (JNIEnv * env, jobject, jint t, jint randomNum){
	  //call the function that does the initialization.
	  initField(t, randomNum);
}

/* function initField : Initialize the field GF2E with irreducible polynomial.
 * param t			  : degree of the irreducible polynomial
 * param randomNum	  : seed for the random calculations.
 */
void initField(jint t, jint randomNum){
	//Create an irreducible polynomial.
	  GF2X irredPoly = BuildSparseIrred_GF2X(t);

	  //init the field with the newly generated polynomial.
	  GF2E::init(irredPoly);
	  
	  //Sets the seed to the random calculations.
	  ZZ seed;
	  seed = (int) randomNum;
	  SetSeed(seed);
}

/* function createRandomFieldElements : Samples random field elements in the GF2E field, 
										return their coefficients in the return value and set their pointers to the pointerToElements argument.
 * param numElements				  : number of elements to sample
 * param pointerToElements		      : an array to fill with the sampled elements' pointers.
 * return jobjectArray				  : array of element's coefficients
 */
JNIEXPORT jobjectArray JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleProverComputation_createRandomFieldElements
  (JNIEnv * env, jobject, jint numElements, jlongArray pointerToElements){
	 
	  //call the function that samples the elements.
	  return sampleRandomFieldElements(env, numElements, pointerToElements);
}

/* function sampleRandomFieldElements : Samples random field elements in the GF2E field, 
										return their coefficients in the return value and set their pointers to the pointerToElements argument.
 * param numElements				  : number of elements to sample
 * param pointerToElements		      : an array to fill with the sampled elements' pointers.
 * return jobjectArray				  : array of element's coefficients
 */
jobjectArray sampleRandomFieldElements(JNIEnv * env, jint numElements, jlongArray pointerToElements){
	
	  jclass byteArrCls = env->FindClass("[B") ; //Define byte class
	  //create object array that will hold the challenges.
	  jobjectArray outChallenges = env->NewObjectArray(numElements, byteArrCls, NULL); 
	  
	  jlong* pointers = env->GetLongArrayElements(pointerToElements, 0);
	  
	  //Samples random elements, puts their bytes in the output array and put their addresses in the pointers array.
	  for (int i=0; i<numElements; i++){
		  //sample random field element.
		  GF2E* element = new GF2E;
		  *element = random_GF2E();

		  //Get the bytes of the random element.
		  jbyteArray elArr = env->NewByteArray(NumBytes(rep(*element)));
		  jbyte* el = env->GetByteArrayElements(elArr, 0);
		  convertGF2EToBytes(*element, el);
		  
		  //put the bytes of the random element in the output array.
		  env->SetObjectArrayElement(outChallenges, i, elArr);
		 
		  env->ReleaseByteArrayElements(elArr, el, 0);
		  //put the element address in the pointers array
		  pointers[i] = (jlong)element;

	  }

	  //release the allocated memory
	  env->ReleaseLongArrayElements(pointerToElements, pointers, 0);
	  
	  return outChallenges;
}



/* function convertGF2EToBytes : Get the bytes of the random element.
 * param element			   : element to convert to bytes
 * param byteArr		       : array that will contain the bytes
 *return int				   : number of byte of the created polynomial.
 */
void convertGF2EToBytes(GF2E element, jbyte* byteArr){
	 
	GF2X fromEl = rep(element); //convert the GF2E element to GF2X element.
	 int numBytes = NumBytes(fromEl); //get the number of element bytes.
	 //the function rep returns the representation of GF2E as the related GF2X, it returns as read only.
	 BytesFromGF2X((unsigned char *)byteArr, fromEl, numBytes);
}

/* function convertBytesToGF2E : crate GF2E element from byte array
 * param env				   : jni environment
 * param byteArr			   : bytes of the element
 * return GF2E				   : the created element.
 */
GF2E convertBytesToGF2E(JNIEnv * env, jbyteArray byteArr){
	//convert to native object.
	jbyte* bytes = env->GetByteArrayElements(byteArr, 0);
	
	//translate the bytes into a GF2X element.
	GF2X e; 
	GF2XFromBytes(e, (unsigned char*)bytes, env->GetArrayLength(byteArr));
	env->ReleaseByteArrayElements(byteArr, bytes, 0);
	
	//convert the GF2X to GF2E
	return to_GF2E(e);
}


/* function interpolate		: Interpolate the points to get a polynomial.
 * param t				    : polynomials degree
 * param challenge		    : verifier's challenge
 * param fieldElements		: pointers to the pre calculated GF2E polynomials.
 * param sampledIndexes		: indexes of the pre calculated GF2E polynomials, such that the points are (sampledIndexes[i], fieldElements[i]).
 * return jlong				: pointer to the interpolated polynomial.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleProverComputation_interpolate
  (JNIEnv * env, jobject, jbyteArray challenge, jlongArray fieldElements, jintArray sampledIndexes){
	  
	  //Call the function that does the interpolate.
	  return interpolate(env, challenge, fieldElements, sampledIndexes);
	
}

/* function interpolate		: Interpolate the points to get a polynomial.
 * param t				    : polynomials degree
 * param challenge		    : verifier's challenge
 * param fieldElements		: pointers to the pre calculated GF2E polynomials.
 * param sampledIndexes		: indexes of the pre calculated GF2E polynomials, such that the points are (sampledIndexes[i], fieldElements[i]).
 * return jlong				: pointer to the interpolated polynomial.
 */
jlong interpolate(JNIEnv * env, jbyteArray challenge, jlongArray fieldElements, jintArray sampledIndexes){
	  //convert to native objects
	  jint* indexes = env->GetIntArrayElements(sampledIndexes, 0);
	
	  //Create vectors of polynomials to the interpolate function.
	  vec_GF2E xVector; //the x coordinates
	  vec_GF2E yVector; //the y coordinates

	  int size = env->GetArrayLength(sampledIndexes);
	 
	  //set the length of the arrays to the number of points + the point (0,e)
	  xVector.SetLength(size+1);
	  yVector.SetLength(size+1);

	  //put the first point in the coordinates arrays.
	  yVector[0] = convertBytesToGF2E(env, challenge);
	  xVector[0] = to_GF2E(0);
	  
	  jlong* bElements  = env->GetLongArrayElements(fieldElements, 0); 
	  
	  //put all the other point in the coordinates arrays.
	  for (int i=0; i<size; i++){
		 
		 //put the challenge polynomial in y array
		 GF2E element = (*(GF2E*)bElements[i]); 
		 yVector[i+1] = element; 
		 
		 //put the index polynomial in x array
		 xVector[i+1] = generateIndexPolynomial(indexes[i]);
	  }

	  
	  //create a GF2EX polynomial 
	  GF2EX* polynomial = new GF2EX;
	  
	  //interpolate the points, put the result polynomial in the created polynomial and return it.
	  interpolate(*polynomial, xVector, yVector);
	  
	  //free the allocated memory
	  env->ReleaseIntArrayElements(sampledIndexes, indexes, 0);
	  env->ReleaseLongArrayElements(fieldElements, bElements, 0);
	  return (jlong)polynomial;
}


GF2E generateIndexPolynomial(int i){
	
	ZZ index;
	index = i;
	unsigned char* indexBytes = new unsigned char[4];
	BytesFromZZ(indexBytes, index, 4);
	
	GF2X indexPoly;
	GF2XFromBytes(indexPoly, (unsigned char*)indexBytes, 4);
	
	delete (indexBytes);
	
	return to_GF2E(indexPoly);
}

/* function getRestChallenges		: Interpolate the points to get a polynomial.
 * param polynomial				    : pointer to the interpolated polynomial
 * param indexesInI					: x coordinates to calculate their y coordinats (the challenges).
 * return jobjectArray				: array of element's coefficients
 */
JNIEXPORT jobjectArray JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleProverComputation_getRestChallenges
  (JNIEnv *env, jobject, jlong polynomial, jintArray indexesInI){
	   
	  //call the function that calculate the rest of the challenges.
	  return calcRestChallenges(env, polynomial, indexesInI);
}

jobjectArray calcRestChallenges(JNIEnv *env, jlong polynomial, jintArray indexesInI){
	
	//convert to native objects
	  GF2EX* polynom = (GF2EX*) polynomial;
	  jint* indexes = env->GetIntArrayElements(indexesInI, 0);

	  int size = env->GetArrayLength(indexesInI);
	  jclass byteArrCls = env->FindClass("[B") ; //Define byte class
	  //create object array that will hold the challenges.
	  jobjectArray outChallenges = env->NewObjectArray(size, byteArrCls, NULL); 

	  //calculate the y coordinate (the challenge) to each one of the indexes (the indexes).
	  for (int i=0; i<size; i++){

		 //get the index polynomial
		 GF2E element = generateIndexPolynomial(indexes[i]);
		 
		 //Evaluate the poltyomial on the index to get the challenge element.
		 GF2E result = eval(*polynom, element);

		 //Get the bytes of the challenge element.
		 jbyteArray elArr = env->NewByteArray(NumBytes(rep(result)));
		 jbyte* el = env->GetByteArrayElements(elArr, 0);
		 convertGF2EToBytes(result, el);
		  
		 //put the bytes of the challenge element in the output array.
		 env->SetObjectArrayElement(outChallenges, i, elArr);
		 env->ReleaseByteArrayElements(elArr, el, 0);
	  }

	  bool valid = true;
	  for (int i=0; i<size; i++){
		  jbyteArray elArr = (jbyteArray)env->GetObjectArrayElement(outChallenges, i);
		  GF2E element = convertBytesToGF2E(env, elArr); 
		  //create the index element
		  GF2E indexElement = generateIndexPolynomial(indexes[i]);
		 
		  //compute Q(i)
		  GF2E result = eval(*polynom, indexElement);
		  //check that Q(i)=ei
		  if (result != element){
				valid = false;
		  }
	  }
	  return outChallenges;
}

/* function getPolynomialBytes		: Return the bytes of the polynomial's coefficients.
 * param poly						: pointer to the interpolated polynomial
 * return jobjectArray				: array of polynomial's coefficients.
 */
JNIEXPORT jobjectArray JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleProverComputation_getPolynomialBytes
  (JNIEnv *env, jobject, jlong poly){
	  
	  //call the function that calculate the polynomial bytes.
	  return calcPolynomialBytes(env, poly);
}

jobjectArray calcPolynomialBytes(JNIEnv *env, jlong poly){
	GF2EX* polynom = (GF2EX*) poly;
	  long degree = deg(*polynom);

	  jclass byteArrCls = env->FindClass("[B") ; //Define byte class
	  //create object array that will hold the challenges.
	  jobjectArray polynomBytes = env->NewObjectArray(degree+1, byteArrCls, NULL); 

	  //convert each coefficient polynomial to byte array and put it in the output array.
	  for (int i=0; i<=degree; i++){
		  //get the coefficient polynomial
		  GF2E coefficient = coeff(*polynom, i);
			
		  //get the bytes of the coefficient.
		  jbyteArray elArr = env->NewByteArray(NumBytes(rep(coefficient)));
		  jbyte* el = env->GetByteArrayElements(elArr, 0);
		  convertGF2EToBytes(coefficient, el);
		    
		  //put the bytes of the coefficient element in the output array.
		  env->SetObjectArrayElement(polynomBytes, i, elArr);
		  env->ReleaseByteArrayElements(elArr, el, 0);
	  }

	  return polynomBytes;
}

/* function deletePointers		: Delete the allocated memory of the polynomial and the field elements.
 * param polynomial				: pointer to the polynomial
 * param fieldElements			: array of pointers to field elements.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleProverComputation_deletePointers
  (JNIEnv * env, jobject, jlong polynomial, jlongArray fieldElements){
	  
	  //call the function that deletes the allocated memory.
	  deleteMemory(env, polynomial, fieldElements);
}

void deleteMemory(JNIEnv *env, jlong polynomial, jlongArray fieldElements){
	 
	  int size = env->GetArrayLength(fieldElements);
	  
	  jlong* elements  = env->GetLongArrayElements(fieldElements, 0); 
	  
	  //delete all field elements.
	  for (int i=0; i<size; i++){
		 delete ((GF2E*)elements[i]); 
	  }

	  //delete the allocated memory for the polynomial.
	  delete((GF2EX*)polynomial);
}

/* function initField : Initialize the field GF2E with irreducible polynomial.
	This function is used by the verifier, while the prover does the same thing.
	The prover' field is different from the verifier's field but the fields are isomorphics so the calculations are correct.
 * param t			  : degree of the irreducible polynomial
 * param randomNum	  : seed for the random calculations.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleVerifierComputation_initField
  (JNIEnv * env, jobject, jint t, jint randomNum){
	 //call the function that does the initialization.
	  initField(t, randomNum);
}

/* function sampleChallenge : Samples random field elements in the GF2E field.
 * param pointerToChallenge	: will hold the pointer to the sampled element
 * return jobjectArray		: array of element coefficients
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleVerifierComputation_sampleChallenge
  (JNIEnv *env, jobject, jlongArray pointerToChallenge){
	  
	//sample random field element.	
	GF2E* element = new GF2E;
	*element = random_GF2E(); 
	
	//get the element's byte.
	jbyteArray elArr = env->NewByteArray(NumBytes(rep(*element)));
	jbyte* el = env->GetByteArrayElements(elArr, 0);
	convertGF2EToBytes(*element, el);
	env->ReleaseByteArrayElements(elArr, el, 0);

	//set the pointer in the argument.
	jlong* pointer = env->GetLongArrayElements(pointerToChallenge, 0);
	pointer[0] = (jlong)element;
	// release the array
	env->ReleaseLongArrayElements(pointerToChallenge, pointer, 0);

	return elArr;
}

JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleVerifierComputation_setChallenge
  (JNIEnv *env, jobject, jlongArray pointerToChallenge, jbyteArray challenge){
	  //sample random field element.	
	GF2E* element = new GF2E;
	*element = convertBytesToGF2E(env, challenge); 
	
	//set the pointer in the argument.
	jlong* pointer = env->GetLongArrayElements(pointerToChallenge, 0);
	pointer[0] = (jlong)element;
	// release the array
	env->ReleaseLongArrayElements(pointerToChallenge, pointer, 0);
}

/* function checkPolynomialValidity : Check if the degree pf the polynom is n-k, if Q(i)=ei for all i=1,…,n and if Q(0)=e.
 * param polynomial					: array of the polynom coefficients
 * param k							: number of true statments. the degree of the polynom should be n-k
 * param verifierChallenge			: pointer to the verifier element
 * param proverChallenges			: array that holds the coeficients of elements in the field
 * param t							: degree of the challenges polynomials.
 * return jboolean					: true if all checks return true.
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleVerifierComputation_checkPolynomialValidity
  (JNIEnv *env, jobject, jobjectArray polynomial, jint k, jlong verifierChallenge, jobjectArray proverChallenges){
	  
	  bool valid = true;
	  GF2EX* polynom = new GF2EX;
	  //Create the polynomial out of the coefficeints array.
	  *polynom = createPolynomial(env, polynomial);
	  
	  //check if the degree of the polynomial os n-k, while n is the number of challenges.
	  int size = env -> GetArrayLength(proverChallenges);
	  if (deg(*polynom) != (size - k)){
		  valid = false;
	  }
	  
	  //check if Q(0)=e.
	  GF2E zero = to_GF2E(0);
	  GF2E e = eval(*polynom, zero); //Q(0)
	  GF2E* challengePointer = (GF2E*) verifierChallenge;
	  if (e != *challengePointer){
		  valid = false;
	  }
	  
	  //for each one of the challenges, check that Q(i)=ei
	  for (int i = 0; i<size; i++){
		  //create the challenge element out of the byte array.
		  jbyteArray challenge = (jbyteArray) env -> GetObjectArrayElement(proverChallenges, i);
	      GF2E challengeElement = convertBytesToGF2E(env, challenge);

		  //create the index element
		  GF2E indexElement = generateIndexPolynomial(i+1);
		 
		  //compute Q(i)
		  GF2E result = eval(*polynom, indexElement);
		  //check that Q(i)=ei
		  if (result != challengeElement){
				valid = false;
		  }
	  }

	  delete(challengePointer);
	  delete(polynom);
	  return valid;
}

/* function createPolynomial : create the polynomial out of the given coefficients array
 * param polynomialBytes	 : byte array of the polynom coefficients
 * param t					 : degree of the challenges polynomials.
 * return GF2EX				 : the created polinomial.
 */
GF2EX createPolynomial(JNIEnv *env, jobjectArray polynomialBytes){
	int deg = env->GetArrayLength(polynomialBytes);
	GF2EX polynom;

	//set each coefficient to the polynomial.
	for (int i=0; i<deg; i++){
		//create the polynomial of the coefficient
		jbyteArray coeff = (jbyteArray) env -> GetObjectArrayElement(polynomialBytes, i);
		
	    //Set the coeeficient to the GF2EX polynomial
	    GF2E coeffElement = convertBytesToGF2E(env, coeff);
		SetCoeff(polynom, i, coeffElement);
	}
	return polynom;
}

/* function initField : Initialize the field GF2E with irreducible polynomial.
	This function is used by the simulator, while the verifier does the same thing.
	The verifier' field is different from the simulator's field but the fields are isomorphics so the calculations are correct.
 * param t			  : degree of the irreducible polynomial
 * param randomNum	  : seed for the random calculations.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleSimulator_initField
  (JNIEnv *env, jobject, jint t, jint randomNum){
	  
	  //call the function that does the initialization.
	  initField(t, randomNum);
}


JNIEXPORT jobjectArray JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleSimulator_createRandomFieldElements
  (JNIEnv *env, jobject, jint numElements, jlongArray pointerToElements){
	  
	  //Call the function that samples the elements.
	  return sampleRandomFieldElements(env, numElements, pointerToElements);
}

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleSimulator_interpolate
  (JNIEnv *env, jobject, jbyteArray challenge, jlongArray fieldElements, jintArray indexes){

	  //Call the function that does the interpolate.
	  return interpolate(env, challenge, fieldElements, indexes);
}

JNIEXPORT jobjectArray JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleSimulator_getRestChallenges
  (JNIEnv *env, jobject, jlong polynomial, jint start, jint end, jintArray indexes){

	  //call the function that calculate the rest of the challenges.
	  return calcRestChallenges(env, polynomial, indexes);
}

JNIEXPORT jobjectArray JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleSimulator_getPolynomialBytes
  (JNIEnv *env, jobject, jlong poly){

	  //call the function that calculate the polynomial bytes.
	  return calcPolynomialBytes(env, poly);
}

JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_sigmaProtocol_orMultiple_SigmaORMultipleSimulator_deletePointers
  (JNIEnv *env, jobject, jlong polynomial, jlongArray fieldElements){

	  //call the function that deletes the allocated memory.
	  deleteMemory(env, polynomial, fieldElements);
}