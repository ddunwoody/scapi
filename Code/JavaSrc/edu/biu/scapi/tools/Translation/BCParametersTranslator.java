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



package edu.biu.scapi.tools.Translation;

import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RC5Parameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

/** 
 * @author LabTest
 */
public final class BCParametersTranslator {
	/** 
	 */
	//create the singleton object
	private final static BCParametersTranslator parametersTranslator = new BCParametersTranslator();
	
	/**
	 * Empty constructor should be private since this class is singleton and we want to prevent user creation
	 * of this class
	 */
	private BCParametersTranslator(){};

	/** 
	 * @return a static instance of BCParametersTranslator
	 */
	public static BCParametersTranslator getInstance() {

		//return the singleton
		return parametersTranslator;
	}

	/** 
	 * Translates the key and the parameters into a CipherParameter of BC. If one of the arguments is null then 
	 * pass to one of the other two translateParameter functions.
	 * @param key the KeySpec to translate to CipherParameters of BC
	 * @param param The additional AlgorithmParametersSpec to transform including the key to relevant CipherParameter
	 */
	public CipherParameters translateParameter(Key key, AlgorithmParameterSpec param) {
	/*
	 * Note - because the translation of a Key to KeySpec is different in each algorithm (some have KeyFactory, some doesn't),
	 * the translation must be specific to the algorithm of the key.
	 * So, although the reasonable parameter to this function is KeySpec, we decided to get a Key instead.
	 * This way the classes that call this function don't need to behave differently in each key type.
	 * In the current implementation, there is no difference between getting KeySpec and Key, 
	 * because the current keys we translate are SecretKey that have just the encoded byte array and RSA key that has get functions in the RSAKey interface.
	 * Id we will need to translate other keys that require translation to KeySpec, we will add it specifically.
	 * 
	 */
		//if one of the arguments is null than pass to one of the other 2 translateParameter functions
		if(key==null){
			return translateParameter(param);
		}
		else if(param==null){
			return translateParameter(key);
		}
		else{
		
			//get the cipher parameter with the key.
			CipherParameters keyparam = translateParameter(key);
			
			if(param instanceof IvParameterSpec){
				//pass the key and the iv
				return new ParametersWithIV(keyparam , ((IvParameterSpec)param).getIV());
			}
		}
		
		return null;
		
	}

	/** 
	 * This function translates a secret key into a <code>KeyParameter</code> or other asymmetric key parameters. 
	 * @param key the key
	 * @return KeyParameter this is used in may of the bc BlockCipher and bc StreamCipher.
	 *         AssymetricKeyParameter for trapdoor permutation and asymmetric encryption
	 */
	public CipherParameters translateParameter(Key key) {
	/*
	 * Note - because the translation of a Key to KeySpec is different in each algorithm (some have KeyFactory, some doesn't),
	 * the translation must be specific to the algorithm of the key.
	 * So, although the reasonable parameter to this function is KeySpec, we decided to get a Key instead.
	 * This way the classes that call this function don't need to behave differently in each key type.
	 * In the current implementation, there is no difference between getting KeySpec and Key, 
	 * because the current keys we translate are SecretKey that have just the encoded byte array and RSA key that has get functions in the RSAKey interface.
	 * Id we will need to translate other keys that require translation to KeySpec, we will add it specifically.
	 * 
	 */
		if (key instanceof SecretKey){
			
			//return the related KeyParameter of BC 
			return new KeyParameter(key.getEncoded()); 
		}
		else if(key instanceof RSAPrivateKey){
			
			//cast the rsa key
			RSAPrivateKey rsaKey = (RSAPrivateKey)key;
			return new RSAKeyParameters(true, rsaKey.getModulus(), rsaKey.getPrivateExponent());
		}
		else if(key instanceof RSAPublicKey){
			
			//cast the rsa key
			RSAPublicKey rsaKey = (RSAPublicKey)key;
			return new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent());
		}
		
		return null;
		
	}

	/** 
	 * This function gets an on object of type AlgorithmParameterSpec and converts it or translates it to a suitable CipherParameters object of
	 * Bouncy Castle, if exists.
	 * @param param the AlgorithmParameterSpec to translate
	 * @return a CipherParameters object from Bouncy Castle that matches the param passed as argument if exists, otherwise returns null
	 */
	public CipherParameters translateParameter(AlgorithmParameterSpec param) {
		
		if(param instanceof RC5ParameterSpec){
			
			RC5ParameterSpec rc5Params = (RC5ParameterSpec)param;
			return new RC5Parameters(rc5Params.getIV(), rc5Params.getRounds());
		}

		
		return null;
		
	}
	
	/** 
	 * Translates the key and the source of randomness into a CipherParameter of BC. If one of the arguments is null then 
	 * pass to one of the other two translateParameter functions.
	 * @param key the Key to translate to CipherParameters of BC
	 * @param random the source of randomness to translate
	 */
	public CipherParameters translateParameter(Key key, SecureRandom random) {
	/*
	 * Note - because the translation of a Key to KeySpec is different in each algorithm (some have KeyFactory, some doesn't),
	 * the translation must be specific to the algorithm of the key.
	 * So, although the reasonable parameter to this function is KeySpec, we decided to get a Key instead.
	 * This way the classes that call this function don't need to behave differently in each key type.
	 * In the current implementation, there is no difference between getting KeySpec and Key, 
	 * because the current keys we translate are SecretKey that have just the encoded byte array and RSA key that has get functions in the RSAKey interface.
	 * Id we will need to translate other keys that require translation to KeySpec, we will add it specifically.
	 * 
	 */
		if(random==null){
			return translateParameter(key);
		}
		else{
		
			//get the cipher parameter with the key.
			CipherParameters keyparam = translateParameter(key);
			
			//pass the key and the random
			return new ParametersWithRandom(keyparam , random);

		}
		
	}
}
