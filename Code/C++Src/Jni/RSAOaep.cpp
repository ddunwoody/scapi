#include "stdafx.h"
#include "RSAOaep.h"
#include "cryptlib.h"
#include "Utils.h"
#include <osrng.h>
#include <rsa.h>
#include <assert.h>

using namespace std;
using namespace CryptoPP;


JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_createRSAEncryptor
  (JNIEnv *, jobject){

	  RSAES_OAEP_SHA_Encryptor* encryptor = new RSAES_OAEP_SHA_Encryptor();

	  //return the encryptor
	  return (jlong) encryptor;
}

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    createRSADecryptor
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_createRSADecryptor
  (JNIEnv *, jobject){
	   
	  RSAES_OAEP_SHA_Decryptor* decryptor = new RSAES_OAEP_SHA_Decryptor();

	  //return the decryptor
	  return (jlong) decryptor;
	  
}



/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    initRSAEncryptor
 * Signature: ([B[B)J
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_initRSAEncryptor
  (JNIEnv *env, jobject, jlong encryptor, jbyteArray modulus, jbyteArray pubExp) {
	  
	  Integer n, e;
	  Utils utils;

	  // get the Integers values for the RSA permutation 
	  n = utils.jbyteArrayToCryptoPPInteger(env, modulus);
	  e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);
	  
	  //create pointer to RSAFunction object
	  RSAFunction* rsaFunc = new RSAFunction(); //assign RSAFunction to the pointer

	  //initialize the RSAFunction object with the RSA values
	  rsaFunc->Initialize(n, e);

	  RSA::PublicKey publicKey(*rsaFunc);
	  ((RSAES_OAEP_SHA_Encryptor * ) encryptor)->AccessPublicKey().AssignFrom(publicKey);
}


/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    initRSADecryptor
 * Signature: ([B[B[B)J
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_initRSADecryptor
  (JNIEnv *env, jobject, jlong decryptor, jbyteArray modulus, jbyteArray pubExp, jbyteArray privExp) {
	  
	  Integer n, e, d;
	  Utils utils;

	  // get the Integers values for the RSA permutation 
	  n = utils.jbyteArrayToCryptoPPInteger(env, modulus);
	  e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);
	  d = utils.jbyteArrayToCryptoPPInteger(env, privExp);

	  //create pointer to InvertibleRSAFunction object
	  InvertibleRSAFunction* invRsaFunc = new InvertibleRSAFunction;

	  //initialize the trapdoor object with the RSA values
	  invRsaFunc->Initialize(n, e, d);

	  RSA::PrivateKey privateKey(*invRsaFunc);
	  
	  ((RSAES_OAEP_SHA_Decryptor * ) decryptor)->AccessKey().AssignFrom(privateKey);
}

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    initRSACrtDecryptor
 * Signature: ([B[B[B[B[B[B[B[B)J
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_initRSACrtDecryptor
  (JNIEnv *env , jobject, jlong decryptor, jbyteArray modulus, jbyteArray pubExp, jbyteArray privExp, jbyteArray prime1, 
  jbyteArray prime2, jbyteArray primeExponent1, jbyteArray primeExponent2, jbyteArray crt) {

	  Integer n, e, d, p, q, dp, dq, u;
	  Utils utils;

	  // get the Integers values for the RSA permutation 
	  n = utils.jbyteArrayToCryptoPPInteger(env, modulus);
	  e = utils.jbyteArrayToCryptoPPInteger(env, pubExp);
	  d = utils.jbyteArrayToCryptoPPInteger(env, privExp);
	  p = utils.jbyteArrayToCryptoPPInteger(env, prime1);
	  q = utils.jbyteArrayToCryptoPPInteger(env, prime2);
	  dp = utils.jbyteArrayToCryptoPPInteger(env, primeExponent1);
	  dq = utils.jbyteArrayToCryptoPPInteger(env, primeExponent2);
	  u = utils.jbyteArrayToCryptoPPInteger(env, crt);

	  //create pointer to InvertibleRSAFunction object
	  InvertibleRSAFunction *invRsaFunc = new InvertibleRSAFunction;

	  //initialize the invert Rsa Function object with the RSA values
	  invRsaFunc-> Initialize(n, e, d, p, q, dp, dq, u);
	  RSA::PrivateKey privateKey(*invRsaFunc);
	  
	  ((RSAES_OAEP_SHA_Decryptor * ) decryptor)->AccessKey().AssignFrom(privateKey);
}

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    doEncrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_doEncrypt
  (JNIEnv * env, jobject, jlong encryptor, jbyteArray msg){
	
	RSAES_OAEP_SHA_Encryptor * encryptorLocal = (RSAES_OAEP_SHA_Encryptor * )encryptor;

	//Sanity checks of size of plaintext
	if(encryptorLocal->FixedMaxPlaintextLength() ==0) 
		return NULL;

	size_t msgLength = env->GetArrayLength(msg);
	if(msgLength > encryptorLocal->FixedMaxPlaintextLength() )
		return NULL;
	
	//Start working
		
	//declare a byte array in c++ where to hold the input msg
	byte *plaintext = (byte*)env->GetByteArrayElements(msg, 0);
	    
	// Create cipher text space
	size_t cipherSize = encryptorLocal->CiphertextLength(msgLength);
	assert( 0 != cipherSize );
	byte *ciphertext = new byte[cipherSize];

	// Actually perform encryption
	AutoSeededRandomPool randPool;
	encryptorLocal->Encrypt( randPool, plaintext, msgLength, ciphertext );

	return (jbyteArray)ciphertext;
}

/*
 * Class:     edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep
 * Method:    doDecrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_doDecrypt
  (JNIEnv * env, jobject, jlong decryptor, jbyteArray cipher){

    RSAES_OAEP_SHA_Decryptor * decryptorLocal = (RSAES_OAEP_SHA_Decryptor * )decryptor;
	//Sanity checks
    if(decryptorLocal->FixedCiphertextLength() ==0 )
		return NULL;
	size_t cipherLength = env->GetArrayLength(cipher);
    if(cipherLength > decryptorLocal->FixedCiphertextLength() )
		return NULL;

    // Create recovered text space
    size_t recoveredMsgLength = decryptorLocal->MaxPlaintextLength(cipherLength);
    assert( 0 != recoveredMsgLength );
 	byte *recovered = new byte[recoveredMsgLength];


    // Decrypt
	AutoSeededRandomPool randPool;
	//declare a byte array in c++ where to hold the input msg
	byte *ciphertext = (byte*)env->GetByteArrayElements(cipher, 0);
    DecodingResult result = decryptorLocal->Decrypt( randPool, ciphertext, cipherLength, recovered );

    // More sanity checks
    if(!result.isValidCoding )
		return NULL;
    if(result.messageLength >  decryptorLocal->MaxPlaintextLength( cipherLength ) )
		return NULL;
   
	return (jbyteArray)recovered;

}


JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_getRSAModulus
  (JNIEnv *env, jobject, jlong encryptor){

	RSAES_OAEP_SHA_Encryptor * encryptorLocal = (RSAES_OAEP_SHA_Encryptor * )encryptor;

	Integer mod = encryptorLocal->GetKey().GetModulus();
	Utils utils;
	return utils.CryptoPPIntegerTojbyteArray (env, mod);
}


JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_midLayer_asymmetricCrypto_encryption_CryptoPPRSAOaep_getPubExponent
  (JNIEnv *env, jobject, jlong encryptor) {
	RSAES_OAEP_SHA_Encryptor * encryptorLocal = (RSAES_OAEP_SHA_Encryptor * )encryptor;
	Integer pubExp = encryptorLocal->GetKey().GetPublicExponent();
	Utils utils;
	return utils.CryptoPPIntegerTojbyteArray (env, pubExp);
}

