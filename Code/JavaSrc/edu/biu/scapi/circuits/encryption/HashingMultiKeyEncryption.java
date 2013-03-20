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
package edu.biu.scapi.circuits.encryption;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidKeySizeException;
import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;

/**
 * We implement this double encryption scheme using Hashing. We use SHA-1. In
 * this encryption scheme the garbled values of each wire are appended to each
 * other and the result is hashed. We XOR the plaintext with the output of the
 * hash function. See <i>Garbling Schemes </i> by Mihir Bellare, Viet Tung
 * Hoang, and Phillip Rogaway for a full discussion on the many different types
 * of garbling schemes and how efficient they are.
 * 
 * @author Steven Goldfeder
 * 
 */
public class HashingMultiKeyEncryption implements MultiKeyEncryptionScheme {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3026420970664946138L;

	/**
	 * Key size in bits. This is the size of the individual keys. One or more
	 * individual keys of this size will be combined into a {@code MultiSecretKey}
	 */
	int keySize; 

	/**
	 * The {@code MultiSecretKey} for this encryption scheme
	 */
	MultiSecretKey key;
	/**
	 * a cryptographically strong random number generator
	 */
	SecureRandom random;
	/**
	 * boolean flag set to {@code true} if the key is set and {@code false}
	 * otherwise
	 */
	boolean isKeySet;
	/**
	 * 
	 */
	private transient CryptographicHash hash;

	/**
	 * @throws FactoriesException
	 * @throws InvalidKeySizeException 
	 */
	public HashingMultiKeyEncryption(int keySize) throws FactoriesException, InvalidKeySizeException {
		if(keySize% 8 != 0){
			throw new InvalidKeySizeException();
		}
		this.keySize = keySize;
		hash = CryptographicHashFactory.getInstance().getObject("SHA-1","CryptoPP");
		random = new SecureRandom();
		isKeySet = false;
	}

	/**
	 * @throws FactoriesException 
	 * 
	 */
	public HashingMultiKeyEncryption() throws FactoriesException {
		
		hash = CryptographicHashFactory.getInstance().getObject("SHA-1","CryptoPP");
	}

	@Override
	public byte[] encrypt(byte[] plaintext)
			throws KeyNotSetException, PlaintextTooLongException {
		
		//CryptographicHash hash = null;
		/*try {
			hash = CryptographicHashFactory.getInstance().getObject("SHA-1");
		} catch (FactoriesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		
		if (!isKeySet) {
			throw new KeyNotSetException();
		}
		// we append all the keys together and hash the result
		for (SecretKey k : key.getKeys()) {
			/*
			 * divide by 8 since the key size is specified in bits and we are using a
			 * byte array
			 */
			hash.update(k.getEncoded(), 0, keySize / 8);
		}
		byte[] output = new byte[20];
		hash.hashFinal(output, 0);
		int offset = output.length - plaintext.length;
		if (offset < 0) {
			/*
			 * the plaintext is longer than the output of the hashed and cannot be
			 * XOR'd to it
			 */
			throw new PlaintextTooLongException();
		}
		if (offset > 0) {
			/*
			 * we truncate the output to the size of the plaintext by using only the
			 * last n bytes where n is the size of the plaintext
			 */

			byte[] temp = new byte[plaintext.length];
			for (int i = 0; i < temp.length; i++) {
				temp[i] = output[i + offset];
			}
			output = temp;
		}
		for (int i = 0; i < output.length; i++) {
			output[i] ^= plaintext[i];
		}
		return output;
	}

	@Override
	public byte[] decrypt(byte[] ciphertext)
			throws KeyNotSetException, CiphertextTooLongException {
		
		
		
		if (!isKeySet()) {
			throw new KeyNotSetException();
		}
		// see comments to encrypt method to understand the encryption/decryption
		for (SecretKey k : key.getKeys()) {
			hash.update(k.getEncoded(), 0, keySize / 8);
		}
		byte[] output = new byte[20];
		hash.hashFinal(output, 0);
		int offset = output.length - ciphertext.length;
		if (offset < 0) {
			throw new CiphertextTooLongException();
		}
		if (offset > 0) {
			byte[] temp = new byte[ciphertext.length];
			for (int i = 0; i < temp.length; i++) {
				temp[i] = output[i + offset];
			}
			output = temp;
		}
		for (int i = 0; i < output.length; i++) {
			output[i] ^= ciphertext[i];
		}
		return output;
	}

	@Override
	public SecretKey generateKey() {
		/*
		 * divide by 8 since the key size is specified in bits and we are using a
		 * byte array
		 */
		byte[] key = new byte[keySize / 8];
		random.nextBytes(key);
		return new SecretKeySpec(key, "");
	}

	@Override
	public MultiSecretKey generateMultiKey(SecretKey... keys) {
		return new MultiSecretKey(keys);
	}

	@Override
	public boolean isKeySet() {
		return isKeySet;
	}

	@Override
	public void setKey(MultiSecretKey key) {
		this.key = key;
		isKeySet = true;
	}

	@Override
	public void setTweak(byte[] tweak) {
		// this encryption scheme ignores the tweak
	}
	
	
	private void readObject(ObjectInputStream inputStream)
            throws IOException, ClassNotFoundException, FactoriesException
    {
		inputStream.defaultReadObject();
		hash = CryptographicHashFactory.getInstance().getObject("SHA-1", "CryptoPP");
    }

	@Override
	/**
	 * Returns the size of the ciphertext
	 */
	public int getCipherSize() {

		return keySize/8;
	}  
}
