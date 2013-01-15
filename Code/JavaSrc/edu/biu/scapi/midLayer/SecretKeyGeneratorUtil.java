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


package edu.biu.scapi.midLayer;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import edu.biu.scapi.primitives.generators.SecretKeyGeneratorSpi;

/**
 * This utility class generates a SecretKey in a single step.
 * There are two possibilities for creation. One requires the size of the key -a value greater than zero-, and the other does not.
 * Both require the name of the algorithm for which to generate the key and a source of randomness. 
 *   
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class SecretKeyGeneratorUtil {
	
	/**
	 * This static function generates a SecretKey. It looks for a default provider implementation for the algorithm name requested.
	 * If found then uses it. Otherwise it creates the Key using {@link SecretKeyGeneratorSpi}.
	 * This function should be used when the key size is known.
	 * It requires a key size greater than zero, otherwise it throws NegativeArraySizeException.
	 * 
	 * @param keySize The size of the requested key in bits.
	 * @param algName The name of the algorithm for which to generate the key.
	 * @param random  The source of randomness to use.
	 * @throws NegativeArraySizeException
	 **/
	static public SecretKey generateKey(int keySize, String algName, SecureRandom random){
		//if the key size is zero or less - throw exception
		if (keySize <= 0){
				throw new NegativeArraySizeException("key size must be greater than 0");
			}
		SecretKey secretKey = null;
		try {
			//Get a default provider KeyGenerator.
			KeyGenerator kGen = KeyGenerator.getInstance(algName);	
			kGen.init(keySize, random);
			secretKey = kGen.generateKey();
		} catch (NoSuchAlgorithmException e) {		
			//Couldn't find default provider implementation-> use SecretKeyGeneratorSpi
			SecretKeyGeneratorSpi keyGen = new SecretKeyGeneratorSpi();
			keyGen.engineInit(keySize, random);
			secretKey = keyGen.engineGenerateKey();
		} 
		return secretKey;

	}
	/**
	 * This static function generates a SecretKey. It looks for a default provider implementation for the algorithm name requested.
	 * If found then uses it. Otherwise it creates the Key using {@link SecretKeyGeneratorSpi}.
	 * This function is useful if there is a default key size for the requested algorithm, 
	 * and there is a default provider implementation for it. 
	 *
	 * @param algName The name of the algorithm for which to generate the key.
	 * @param random  The source of randomness to use.
	 * @throws NoSuchAlgorithmException  
	 **/
	static public SecretKey generateKey(String algName, SecureRandom random) throws NoSuchAlgorithmException{
		SecretKey secretKey = null;
		KeyGenerator kGen = KeyGenerator.getInstance(algName);
		kGen.init( random); //The generator will use its default size.
		secretKey = kGen.generateKey(); 
		return secretKey;

	}
	/**
	 * This static function generates a SecretKey. It looks for a default provider implementation for the algorithm name requested.
	 * If found then uses it. Otherwise it creates the Key using {@link SecretKeyGeneratorSpi}.
	 * This function is useful if there is a default key size for the requested algorithm, 
	 * and there is a default provider implementation for it. 
	 * This function uses SCAPI's default source of randomness.
	 * 
	 * @param algName The name of the algorithm for which to generate the key.
	 * @throws NoSuchAlgorithmException  
	 **/
	static public SecretKey generateKey(String algName) throws NoSuchAlgorithmException{
		SecureRandom random = new SecureRandom();
		return generateKey(algName, random);
	}
}
