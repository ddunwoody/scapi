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


package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * KeyFactory for Rabin keys. Translates Rabin keys to RabinKeySpec and vice versa.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScRabinKeyFactory extends KeyFactorySpi{

	/**
	 * generates a ScRabinPrivateKey from the given keySpec.
	 * @param spec should be ScRabinPrivateKeySpec
	 * @throws InvalidKeySpecException if the gives KeySpec is not an instance of ScRabinPrivateKeySpec
	 */
	public PrivateKey engineGeneratePrivate(KeySpec spec)
			throws InvalidKeySpecException {
	//NOTE - we changed the access member modifier of this function from protected to public
		//checks that the keySpec is of type ScRabinPrivateKeySpec
		if (spec instanceof ScRabinPrivateKeySpec){
			//extracts the rabin private key parameters
			ScRabinPrivateKeySpec privateKeySpec = (ScRabinPrivateKeySpec)spec;
			BigInteger mod = privateKeySpec.getModulus();
			BigInteger p = privateKeySpec.getPrime1();
			BigInteger q = privateKeySpec.getPrime2();
			BigInteger u = privateKeySpec.getInversePModQ();
			//creates new ScRabinPrivateKey with the parameters given in the keySpec
			return new ScRabinPrivateKey(mod, p, q, u);
		}
		//if the given keySpec is not a ScRabinPrivateKeySpec throws exception
		throw new InvalidKeySpecException("KeySpec must be ScRabinPrivateKeySpec");
	}
	
	/**
	 * generates a ScRabinPubliceKey from the given keySpec.
	 * @param spec should be ScRabinPublicKeySpec
	 * @throws InvalidKeySpecException if the gives KeySpec is not an instance of ScRabinPublicKeySpec
	 */
	public PublicKey engineGeneratePublic(KeySpec spec)
			throws InvalidKeySpecException {
	//NOTE - we changed the access member modifier of this function from protected to public
		//checks that the keySpec is of type ScRabinPublicKeySpec
		if (spec instanceof ScRabinPublicKeySpec){
			//extracts the rabin public key parameters
			ScRabinPublicKeySpec publicKeySpec = (ScRabinPublicKeySpec)spec;
			BigInteger mod = publicKeySpec.getModulus();
			BigInteger r = publicKeySpec.getQuadraticResidueModPrime1();
			BigInteger s = publicKeySpec.getQuadraticResidueModPrime2();
			//creates new ScRabinPublicKey with the parameters given in the keySpec
			return new ScRabinPublicKey(mod, r, s);
		}
		//if the given keySpec is not a ScRabinPublicKeySpec throws exception
		throw new InvalidKeySpecException("KeySpec must be ScRabinPublicKeySpec");
	}

	/**
	 * Returns the KeySpec corresponding to the given key.
	 * The returned KeySpec will be of type T, if that is a valid KeySpec for the given key
	 * @throws InvalidKeySpecException if keyDpec is not a valid KeySpec for the given key
	 * or if the given key is not a valid rabin key
	 */
	public <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
			throws InvalidKeySpecException {
	//NOTE - we changed the access member modifier of this function from protected to public
		//converts the given key to SCAPI key
		try {
			key = engineTranslateKey(key);
		//if the key is not a valid rabin key, throw exception
		} catch (InvalidKeyException e) {
			throw new InvalidKeySpecException(e);
		}
		
		if(key instanceof RabinPublicKey){
			if ((ScRabinPublicKeySpec.class).isAssignableFrom(keySpec)) {
				//if the given key is a RabinPublicKey and the given keySpec is 
				//ScRabinPublicKeySpec class, get the key parameters and creates a ScRabinPublicKeySpec
				RabinPublicKey publicKey = (RabinPublicKey)key;
				BigInteger mod = publicKey.getModulus();
				BigInteger r = publicKey.getQuadraticResidueModPrime1();
				BigInteger s = publicKey.getQuadraticResidueModPrime2();
				return (T) new ScRabinPublicKeySpec(mod, r, s);
			}
			//if the keySpec is not a ScRabinPublicKeySpec class, throws exception
			throw new InvalidKeySpecException ("KeySpec must be ScRabinPublicKeySpec");
        }
		if (key instanceof RabinPrivateKey){
			if ((ScRabinPrivateKeySpec.class).isAssignableFrom(keySpec)) {
				//if the given key is a RabinPrivateKey and the given keySpec is 
				//ScRabinPrivateKeySpec class, get the key parameters and creates a ScRabinPrivateKeySpec
				RabinPrivateKey publicKey = (RabinPrivateKey)key;
				BigInteger mod = publicKey.getModulus();
				BigInteger p = publicKey.getPrime1();
				BigInteger q = publicKey.getPrime2();
				BigInteger u = publicKey.getInversePModQ();
				return (T) new ScRabinPrivateKey(mod, p, q, u);
			}
			//if the keySpec is not a ScRabinPrivateKeySpec class, throws exception
			throw new InvalidKeySpecException ("KeySpec must be ScRabinPrivateKeySpec");
		}
		//if the key is not public or private key, throws exception
		throw new InvalidKeySpecException("Key must be RabinPublicKey or RabinPrivateKey");
	}

	/**
	 * Translate RabinKey to SCAPI key
	 */
	public Key engineTranslateKey(Key key) throws InvalidKeyException {
	//NOTE - we changed the access member modifier of this function from protected to public
		if(key == null){
			throw new InvalidKeyException("Key must not be null");
		}
		//if the key is not rabin key - throws exception
		if (key.getAlgorithm().compareTo("Rabin") != 0){
			throw new InvalidKeyException("Key must be instance of Rabin key");
		}
		//key is RabinPublicKey - creates a ScRabinPublicKey
		if (key instanceof RabinPublicKey){
			if(key instanceof ScRabinPublicKey){
				return key;
			}
			RabinPublicKey publicKey = (RabinPublicKey)key;
			BigInteger mod = publicKey.getModulus();
			BigInteger r = publicKey.getQuadraticResidueModPrime1();
			BigInteger s = publicKey.getQuadraticResidueModPrime2();
			return new ScRabinPublicKey(mod, r, s);
		}
		//key is RabinPrivateKey - creates a ScRabinPrivateKey
		if (key instanceof RabinPrivateKey){
			if(key instanceof ScRabinPrivateKey){
				return key;
			}
			RabinPrivateKey publicKey = (RabinPrivateKey)key;
			BigInteger mod = publicKey.getModulus();
			BigInteger p = publicKey.getPrime1();
			BigInteger q = publicKey.getPrime2();
			BigInteger u = publicKey.getInversePModQ();
			return new ScRabinPrivateKey(mod, p, q, u);
		}
		//if the key is not public or private - throws exception
		throw new InvalidKeyException("key must be RabinPublicKey or RabinPrivateKey");
	}

}
