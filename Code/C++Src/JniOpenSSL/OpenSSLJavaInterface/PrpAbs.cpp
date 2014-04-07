#include "StdAfx.h"
#include <jni.h>
#include "PrpAbs.h"
#include <openssl/evp.h>
#include <iostream>

using namespace std;

/* 
 * function computeBlock		: Compute the PRP on the given block.
 * param prp					: pointer to the PRP object.
 * param in						: The input block to cumpute the permutation on.
 * param out					: The output block to hold the permutation result.
 * param outOffset				: The offset within the output array to put the result from.
 * param blockSize				: The block size of the given prp.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLPRP_computeBlock
  (JNIEnv *env, jobject, jlong prp, jbyteArray in, jbyteArray out, jint outOffset, jint blockSize){
	  //Convert the given data into c++ notation.
	  jbyte* input  = (jbyte*) env->GetByteArrayElements(in, 0);
	  int size;
	  
	  //Allocate a new byte array with the size of the specific prp algorithm.
	  unsigned char* ret = new unsigned char[blockSize]; 

	  //Compute the prp on the given input array, put the result in ret.
	  EVP_EncryptUpdate ((EVP_CIPHER_CTX*)prp, ret, &size, (unsigned char*)input, blockSize);
	  
	  //Put the result of the final computation in the output array passed from java.
	  env->SetByteArrayRegion(out, outOffset, blockSize, (jbyte*)((char*)ret)); 
	  
	  //Make sure to release the dynamically allocated memory. Will not be deleted by the JVM.
	  delete ret;
	  env->ReleaseByteArrayElements(in, input, 0);
}

/* 
 * function invertBlock			: inverts the PRP on the given block.
 * param prp					: pointer to the PRP object.
 * param in						: The input block to invert the permutation on.
 * param out					: The output block to hold the permutation result.
 * param outOffset				: The offset within the output array to put the result from.
 * param blockSize				: The block size of the given prp.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLPRP_invertBlock
  (JNIEnv *env, jobject, jlong prp, jbyteArray in, jbyteArray out, jint outOffset, jint blockSize){
	  //Convert the given data into c++ notation.
	  jbyte* input  = (jbyte*) env->GetByteArrayElements(in, 0);
	  
	  //Allocate a new byte array with the size of the specific prp algorithm.
	  unsigned char* ret = new unsigned char[env->GetArrayLength(out)]; 
	  int size;
	  
	  //Invert the prp on the given input array, put the result in ret.
	  EVP_DecryptUpdate ((EVP_CIPHER_CTX*)prp, ret, &size, (unsigned char*)input, blockSize);
	  
	  //Put the result of the final computation in the output array passed from java.
	  env->SetByteArrayRegion(out, outOffset, blockSize, (jbyte*)((char*)ret)); 
	  
	  //Make sure to release the dynamically allocated memory. Will not be deleted by the JVM.
	  delete ret;
	  env->ReleaseByteArrayElements(in, input, 0);
}

/* 
 * function doOptimizedCompute		: Compute the PRP on the given input array. The array can be longer than one block.
 * param prp						: pointer to the PRP object.
 * param inBytes					: The input array to cumpute the permutation on.
 * param outBytes					: The output array to hold the permutation result.
 * param blockSize					: The block size of the given prp.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLPRP_doOptimizedCompute
  (JNIEnv *env, jobject, jlong prp, jbyteArray inBytes, jbyteArray outBytes, jint blockSize){
	  //Convert the arrays into c++ notation.
	  jbyte *in = env->GetByteArrayElements(inBytes, 0);
	  
	  //Calculate the number of blocks in the given input array.
	  //int rounds = (env->GetArrayLength(inBytes))/blockSize;
	  int size = env->GetArrayLength(inBytes);
	  //Allocate a new byte array with the block size of the specific prp algorithm.
	  unsigned char* outBlock = new unsigned char[size];
	  //int size;
	  
	  EVP_EncryptUpdate ((EVP_CIPHER_CTX*)prp, outBlock, &size, (unsigned char*)in, size);
	  env->SetByteArrayRegion(outBytes, 0, size, (jbyte*)outBlock);
	  //Compute the prp on each block and put the result in the output array.
	  //for (int i=0; i<rounds; i++){
		  
		  //Compute the block.
		 // EVP_EncryptUpdate ((EVP_CIPHER_CTX*)prp, outBlock, &size, (unsigned char*)in+(i*blockSize), blockSize);

		  //Put the result in the given output array in the right place.
		 // env->SetByteArrayRegion(outBytes, i*blockSize, blockSize, (jbyte*)outBlock);
	 // }

	  //Mke sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(inBytes,in,0);
	  delete (outBlock);
}

/* 
 * function doOptimizedInvert		: Inverts the PRP on the given input array. The array can be longer than one block.
 * param prp						: pointer to the PRP object.
 * param inBytes					: The input array to invert the permutation on.
 * param outBytes					: The output array to hold the permutation result.
 * param blockSize					: The block size of the given prp.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLPRP_doOptimizedInvert
  (JNIEnv *env, jobject, jlong prp, jbyteArray inBytes, jbyteArray outBytes, jint blockSize){
	  //Convert the arrays into c++ notation.
	  jbyte *in = env->GetByteArrayElements(inBytes, 0);
	  
	  //Calculate the number of blocks in the given input array.
	  //int rounds = (env->GetArrayLength(inBytes))/blockSize;
	 int size = env->GetArrayLength(inBytes);
	  //Allocate a new byte array with the block size of the specific prp algorithm.
	  unsigned char* outBlock = new unsigned char[size];
	  //int size;
	  EVP_DecryptUpdate ((EVP_CIPHER_CTX*)prp, outBlock, &size, (unsigned char*)(in), size);

	  env->SetByteArrayRegion(outBytes, 0, size, (jbyte*)outBlock);  
	  //Invert the prp on each block and put the result in the output array.
	 /* for (int i=0; i<rounds; i++){
		 
		  //Invert the block.
		  int suc = EVP_DecryptUpdate ((EVP_CIPHER_CTX*)prp, outBlock, &size, (unsigned char*)(in+(i*blockSize)), blockSize);
		  
		  //Put the result in the given output array in the right place.
		  env->SetByteArrayRegion(outBytes, i*blockSize, blockSize, (jbyte*)outBlock);  
	  }*/

	  //Make sure to release the memory created in c++. The JVM will not release it automatically.
	  env->ReleaseByteArrayElements(inBytes,in,0);
	  delete (outBlock);
}

/* 
 * function deleteNative		: Delete the native objects.
 * param computeP				: pointer to the PRP object that does encryption.
 * param invertP				: pointer to the PRP object that does decryption.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLPRP_deleteNative
  (JNIEnv *, jobject, jlong computeP, jlong invertP){
	  EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX*)computeP);
	  EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX*)invertP);
	  EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)computeP);
	  EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)invertP);
}