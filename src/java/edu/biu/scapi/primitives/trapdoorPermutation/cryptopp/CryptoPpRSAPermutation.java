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


package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.trapdoorPermutation.RSAPermutation;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElValidity;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutationAbs;

/**
 * Concrete class of trapdoor permutation of RSA.
 * This class wraps the crypto++ implementation of RSA permutation
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public final class CryptoPpRSAPermutation extends TrapdoorPermutationAbs implements RSAPermutation {

	private long tpPtr; //pointer to the RSA native object
	private SecureRandom random;
	
	// native functions. These functions are implemented in the CryptoPPJavaInterface dll using the JNI.
	
	//initializes RSA permutation with public and private keys
	private native long initRSAPublicPrivate(byte[] modulus, byte[] pubExponent, byte[] privExponent);
	//initializes RSA permutation with public and crt private keys
	private native long initRSAPublicPrivateCrt(byte[] modulus, byte[] pubExponent, byte[] privExponent, 
									   byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] crt);
	//initializes RSA permutation with public key
	private native long initRSAPublic(byte[] modulus, byte[] pubExponent);
	
	//returns the algorithm name - RSA
	private native String loadRSAName(long ptr);
	//checks if the given element value is valid for this RSA permutation
	private native boolean checkRSAValidity(long value, long ptr);
	
	//computes RSA permutation
	private native long computeRSA(long tpr, long x);
	//inverts RSA permutation
	private native long invertRSA(long ptr, long y);
	
	//deletes the native object
	private native void deleteRSA(long ptr);
	
	
	public CryptoPpRSAPermutation(){
		this(new SecureRandom());
	}
	
	public CryptoPpRSAPermutation(SecureRandom random){
		this.random = random;
	}
	
	public CryptoPpRSAPermutation(String randNumGenAlg) throws NoSuchAlgorithmException{
		this(SecureRandom.getInstance(randNumGenAlg));
	}
	
	
	/** 
	 * Initializes this RSA with public and private keys
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException if the given keys are not RAE keys
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
			
		if (!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
			
		/* gets the values of modulus (N), pubExponent (e), privExponent (d)*/
		BigInteger pubExponent = ((RSAPublicKey) publicKey).getPublicExponent();
		BigInteger privExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
		modulus = ((RSAKey) publicKey).getModulus();
		
		//if private key is CRT private key
		if (privateKey instanceof RSAPrivateCrtKey)
		{
			//gets all the crt parameters
			RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
			BigInteger p = key.getPrimeP();
			BigInteger q = key.getPrimeQ();
			BigInteger dp = key.getPrimeExponentP();
			BigInteger dq = key.getPrimeExponentQ();
			BigInteger crt = key.getCrtCoefficient();
			
			//initializes the native object
			tpPtr = initRSAPublicPrivateCrt(modulus.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray(), 
					p.toByteArray(), q.toByteArray(), dp.toByteArray(), dq.toByteArray(), crt.toByteArray());
			
		//if private key is key with N, e, d
		} else {
			
			//init the native object with the RSA parameters - n, e, d
			tpPtr = initRSAPublicPrivate(modulus.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray());
		}
		
		//calls the parent init that sets the keys
		super.setKey(publicKey, privateKey);
		
	}

	/** 
	 * Initializes this RSA permutation with public key
	 * @param publicKey - public key
	 * @throws InvalidKeyException if the key is not RSA key
	 */
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
			
		if (!(publicKey instanceof RSAPublicKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
			
		RSAPublicKey pub = (RSAPublicKey) publicKey;
		BigInteger pubExponent = pub.getPublicExponent();
		modulus = pub.getModulus();
		
		//init the native object with the RSA public parameters - n, e
		tpPtr = initRSAPublic(modulus.toByteArray(), pubExponent.toByteArray());

		//calls the parent init
		super.setKey(publicKey);
	}

	/** 
	 * @return the algorithm name - RSA
	 */
	public String getAlgorithmName() {
		
		return loadRSAName(tpPtr);
	}
	
	/** 
	 * Generate RSA public and private keys.
	 * @param params RSAKeyGenParameterSpec
	 * @throws InvalidParameterSpecException if params are not RSA parameter spec
	 */
	public KeyPair generateKey(AlgorithmParameterSpec params) throws InvalidParameterSpecException {
		KeyPair pair = null;
		if(!(params instanceof RSAKeyGenParameterSpec)) {
			throw new InvalidParameterSpecException("AlgorithmParameterSpec type doesn't match the trapdoor permutation type");
		}
	
		try {
			/*generates public and private keys */
			KeyPairGenerator kpr;
			kpr = KeyPairGenerator.getInstance("RSA");
			kpr.initialize(((RSAKeyGenParameterSpec) params).getKeysize(), random);
			pair = kpr.generateKeyPair();
			
		} catch (NoSuchAlgorithmException e) {
			//shouldn't occur since RSA is a  valid algorithm
			Logging.getLogger().log(Level.WARNING, e.toString());
		} 
		
		return pair;
	}
	
	/**
	 * This function is not supported in this implementation. Throws exception.
	 * @throws UnsupportedOperationException 
	 */
	public KeyPair generateKey(){
		throw new UnsupportedOperationException("To generate keys for this RSA object use the generateKey(AlgorithmParameterSpec params) function");
	}

	/** 
	 * Computes the RSA permutation on the given TPElement
	 * @param tpEl - the input for the computation
	 * @return - the result element
	 * @throws - IllegalArgumentException if the given element is not RSA element
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException{
		
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		// gets the pointer for the native object
		long elementP = ((CryptoPpRSAElement)tpEl).getPointerToElement(); 
		
		//calls for the native function
		long result = computeRSA(tpPtr, elementP); 
		
		//creates and initializes CryptoPpRSAElement with the result
		CryptoPpRSAElement returnEl = new CryptoPpRSAElement(result);
		
		return returnEl; // returns the result TPElement
	}
	
	/**
	 * Inverts the RSA permutation on the given element 
	 * @param tpEl - the input to invert
	 * @return - the result 
	 * @throws KeyException 
	 * @throws - IllegalArgumentException
	 */
	public TPElement invert(TPElement tpEl) throws IllegalArgumentException, KeyException{
		
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		

		//If the key set was only the public key and not the private key - can't do the invert, throw exception.
		if (privKey == null && pubKey!=null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		//gets the pointer for the native object
		long elementP = ((CryptoPpRSAElement)tpEl).getPointerToElement();
		
		//calls for the native function
		long result = invertRSA(tpPtr, elementP); 
		
		//creates and initialize CryptoPpRSAElement with the result
		CryptoPpRSAElement returnEl = new CryptoPpRSAElement(result);
		
		return returnEl; // returns the result TPElement
	}
	
	/** 
	 * Checks if the given element is valid for this RSA permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * There are three possible validity values: 
	 * VALID (it is an element)
	 * NOT_VALID (it is not an element)
	 * DON’T_KNOW (there is not enough information to check if it is an element or not)  
	 * @throws - IllegalArgumentException if the given element is invalid for this RSA permutation
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException{

		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		TPElValidity validity = null;
		long value = ((CryptoPpRSAElement)tpEl).getPointerToElement();
		
		//if the trapdoor permutation is unknown - returns DONT_KNOW 
		if (modulus == null) {
			validity = TPElValidity.DONT_KNOW;
		
		//if the value is valid (between 1 to (mod n) - 1) returns VALID 
		} else if(checkRSAValidity(value, tpPtr)) {
			
			validity = TPElValidity.VALID;
		//if the value is invalid returns NOT_VALID 
		} else {
			validity = TPElValidity.NOT_VALID;
		}		
		
		//returns the correct TPElValidity
		return validity;
	}

	/** 
	 * creates a random CryptoPpRSAElement
	 * @return TPElement - the created random element 
	 */
	public TPElement generateRandomTPElement() {

		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		return new CryptoPpRSAElement(modulus);
	}
	
	@Override
	public TPElement generateTPElement(BigInteger x) throws IllegalArgumentException {
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		return new CryptoPpRSAElement(modulus, x, true);
	}
	
	public TPElement generateUncheckedTPElement(BigInteger x) throws IllegalArgumentException {
		/*if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		*/
		return new CryptoPpRSAElement(modulus, x, false);
	}
	
	/**
	 * deletes the native RSA object
	 */
	protected void finalize() throws Throwable {
		
		//deletes from the dll the dynamic allocation of the RSA permutation.
		deleteRSA(tpPtr);
		
		super.finalize();
	}
	
	//loads the dll
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }

	
	
	
	
}
