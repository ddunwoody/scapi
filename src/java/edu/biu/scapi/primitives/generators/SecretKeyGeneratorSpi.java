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


package edu.biu.scapi.primitives.generators;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * General class for generating secret keys.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SecretKeyGeneratorSpi extends KeyGeneratorSpi{

	private String algorithmName = ""; 	//the algorithm name of the required key.
										//initializes to empty string instead of null so if it won't set to other name 
										//the search for this algorithm will cause exception of type "NoSuchAlgorithm" and not "NullPointer"
	private int keySize = 0; 				//the required key size
	private SecureRandom random = null;		//source of randomness
	private boolean isInitialized = false;
	
	/**
	 * Empty constructor, as required in the provider architecture.
	 */
	public SecretKeyGeneratorSpi() {}
	
	/**
	 * SecretKeyGeneratorSpi should get keySize or AlgorithmParameterSpec in the initialization.
	 * If the user calls this init function, throw exception.
	 * @throws UnsupportedOperationException
	 */
	protected void engineInit(SecureRandom rnd) {
		throw new UnsupportedOperationException("LubyRackoffKeyGeneratorSpi should be initialized with AlgorithmParameterSpec and a secureRandom");
	}

	/**
	 * initializes SecretKeyGeneratorSpi with AlgorithmParameterSpec and a secureRandom.
	 * The AlgorithmParametersSpec should be instance of SecretKeyGeneratorParameterSpec, which contains keySize and algorithmName.
	 * If the keySize inside the SecretKeyGeneratorParameterSpec is 0 - the size of the key will be the default key size as implemented in the provider of the algorithm.
	 * @param params the generator auxiliary parameters
	 * @param rnd secure random
	 */
	protected void engineInit(AlgorithmParameterSpec params, SecureRandom rnd)
			throws InvalidAlgorithmParameterException {
		//the AlgorithmParameterSpec should be instance of SecretKeyGeneratorParameterSpec
		if (!(params instanceof SecretKeyGeneratorParameterSpec)){
			throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec should be instance of SecretKeyGeneratorParameterSpec");
		}
		//sets the parameters
		this.algorithmName = ((SecretKeyGeneratorParameterSpec) params).getAlgorithmName();
		this.keySize = ((SecretKeyGeneratorParameterSpec) params).getKeySize();
		random = rnd;
		//marks this object as initialized
		isInitialized = true;
	}

	/**
	 * initializes SecretKeyGeneratorSpi with key size and a secureRandom.
	 * The keySize should be greater than zero. otherwise - throws exception
	 * @param keySize the required key size in bits
	 * @param rnd secure random
	 * @throws InvalidParameterException if the keySize is not greater than zero
	 */
	public void engineInit(int keySize, SecureRandom rnd) {
	//Note - we changed the visibility of this function from protected to public in order to be able to call it from our project classes
		//key size should be greater than 0
		if (keySize <= 0){
			throw new InvalidParameterException("key size must be greater than 0");
		}
		//sets the parameters
		this.keySize = keySize;
		random = rnd;
		//marks this object as initialized
		isInitialized = true;
	}

	/**
	 * Generates secretKey according to the parameters given in the init functions.
	 * @return SecretKey the generated key
	 */
	public SecretKey engineGenerateKey() {
	//Note - we changed the visibility of this function from protected to public in order to be able to call it from our project classes
		/*
		 * if the given algorithm is known algorithm
		 * and there is a keyGenerator for this algorithm in the providers - 
		 * create the key using this keyGenerator.
		 */
		try {
			//gets the KeyGenerator of this algorithm
			KeyGenerator keyGen = KeyGenerator.getInstance(algorithmName);
			//if the key size is zero or less - uses the default key size as implemented in the provider implementation
			if(keySize <= 0){
				keyGen.init(random);
			//else, uses the keySize to generate the key
			} else {
				keyGen.init(keySize, random);
			}
			//generates the key
			return keyGen.generateKey();
		/*
		 * if the algorithm was not given, or there is no such algorithm in the current providers, 
		 * generates the key using the given random 
		 */
		} catch (NoSuchAlgorithmException e) {
			if (!isInitialized){
				throw new IllegalStateException("SecretKeyGeneratorSpi must be initialized before used");
			}
			//if the key size is zero or less - throw exception
			if (keySize <= 0){
				throw new NegativeArraySizeException("key size must be greater than 0");
			}
			//creates a byte array of size keySize
			byte[] genBytes = new byte[keySize];
			//if the random is null uses SecureRandom
			if (random == null){
				random = new SecureRandom();
			}
			//generates the bytes using the random
			random.nextBytes(genBytes);
			//creates a secretKey from the generated bytes
			SecretKey genKey = new SecretKeySpec(genBytes, "");
			return genKey;
		}
	}
}
