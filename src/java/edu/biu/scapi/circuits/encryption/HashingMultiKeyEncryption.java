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
 * We implement this double encryption scheme using Hashing. <p>
 * In this encryption scheme the garbled values of each wire are appended to each other and the result is hashed. 
 * We XOR the plaintext with the output of the hash function. <p>
 * See <i>Garbling Schemes </i> by Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway for a full discussion on the many different types
 * of garbling schemes and how efficient they are.
 * 
 * @author Steven Goldfeder
 * 
 */
public class HashingMultiKeyEncryption implements MultiKeyEncryptionScheme {

	/*
	 * Key size in bits. This is the size of the individual keys. 
	 * One or more individual keys of this size will be combined into a {@code MultiSecretKey}.
	 */
	private int keySize; 

	//The {@code MultiSecretKey} for this encryption scheme.
	private MultiSecretKey key;
	
	//A cryptographically strong random number generator.
	private SecureRandom random;
	
	// Boolean flag set to {@code true} if the key is set and {@code false} otherwise.
	private boolean isKeySet;

	private CryptographicHash hash;

	/**
	 * Constructor that sets the given values.
	 * @throws InvalidKeySizeException 
	 */
	public HashingMultiKeyEncryption(int keySize, CryptographicHash hash, SecureRandom random) throws InvalidKeySizeException {
		doConstruct(keySize, hash, random);
	}

	/**
	 * Constructor that sets default values.
	 */
	public HashingMultiKeyEncryption()  {
		
		try {
			doConstruct(80, CryptographicHashFactory.getInstance().getObject("SHA-1","CryptoPP"), new SecureRandom());
		} catch (InvalidKeySizeException e) {
			// shouldn't occur since the given key size is correct.
		} catch (FactoriesException e) {
			// Should not occur since the arguments to the factory are correct.
		}
	}

	private void doConstruct(int keySize, CryptographicHash hash, SecureRandom random) throws InvalidKeySizeException {
		if(keySize% 8 != 0){
			throw new InvalidKeySizeException();
		}
		this.keySize = keySize;
		this.hash = hash;
		this.random = random;
	}
	
	@Override
	public byte[] encrypt(byte[] plaintext) throws KeyNotSetException, PlaintextTooLongException {
		
		
		if (!isKeySet) {
			throw new KeyNotSetException();
		}
		// Append all the keys together and hash the result.
		for (SecretKey k : key.getKeys()) {
			//Divide by 8 since the key size is specified in bits and we are using a byte array.
			hash.update(k.getEncoded(), 0, keySize / 8);
		}
		byte[] output = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(output, 0);
		int offset = output.length - plaintext.length;
		if (offset < 0) {
			// The plaintext is longer than the output of the hashed and cannot be XOR'd to it.
			throw new PlaintextTooLongException();
		}
		if (offset > 0) {
			//Truncate the output to the size of the plaintext by using only the last n bytes where n is the size of the plaintext.
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
		// See comments to encrypt method to understand the encryption/decryption.
		for (SecretKey k : key.getKeys()) {
			hash.update(k.getEncoded(), 0, keySize / 8);
		}
		byte[] output = new byte[hash.getHashedMsgSize()];
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
		//Divide by 8 since the key size is specified in bits and we are using a byte array
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
		// This encryption scheme ignores the tweak
	}

	@Override
	/**
	 * Returns the size of the ciphertext.
	 */
	public int getCipherSize() {

		return keySize/8;
	}  
}
