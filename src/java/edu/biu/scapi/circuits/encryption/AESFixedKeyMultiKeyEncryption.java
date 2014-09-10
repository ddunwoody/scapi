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

import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.security.InvalidKeyException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.TweakNotSetException;
import edu.biu.scapi.primitives.prf.AES;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;

/**
 * This encryption scheme uses AES with a fixed key and thus has the benefit of not needing to repeatedly perform the costly setKey 
 * procedure for AES. See <i>Garbling Schemes </i> by Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway Section 5.6 for a full 
 * description of this encryption scheme. <p>
 * 
 * This encryption scheme works by XORing all of the wire values(i.e. keys) to each other and then XORing this to the tweak. 
 * This value is denoted by K. We call AES with the fixed key on K and then XOR the result of that to K and then to the plaintext to encrypt.
 * 
 * @author Steven Goldfeder
 * 
 */
public class AESFixedKeyMultiKeyEncryption implements MultiKeyEncryptionScheme {

	//The number of bits in the key. It is currently set to 128, and the {@code FIXED_KEY} field is this size.
	static final int KEY_SIZE = 128; 
	
	//A 128 bit key that we generated once and hardcoded in.
	static final SecretKey FIXED_KEY = new SecretKeySpec (new byte[]{ -13, 29,-20, 98, -96, -51, -86, -82, 9, 49, -26, 92, -22, 50, -100, 36 }, "");
	
	private AES aes;
	
	/*
	 * The key here is not the key to the AES, but rather the key to this encryption scheme. 
	 * See Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway Section 5.6 or see the encrypt(plaintext),
	 * decrypt(ciphertext) methods below to see how these keys are used in encrpytion/decryption.
	 */
	private MultiSecretKey key;

	//For the tweak, we use the gate number followed by the signal bits for each of the input wires.
	private byte[] tweak;
	
	//{@code boolean} flag that is {@code true} of the key has been set, {@code false} otherwise
	private boolean isKeySet = false;
	
	//{@code boolean} flag that is {@code true} of the tweak has been set, {@code false} otherwise
	private boolean isTweakSet = false;

	//The regular implementation of encrypt and decrypt are insecure in case of free xor circuit since the delta is revealed.
	//To avoid that, the input to the aes function should be different. 
	//This flag indicates which algorithm to use.
	private boolean isFreeXor = false; 

	public AESFixedKeyMultiKeyEncryption() {
		aes = new CryptoPpAES();
		try {
			aes.setKey(FIXED_KEY);
		} catch (InvalidKeyException e) {
			// This should not occur since the fixed key should be valid.
		}
	}

	@Override
	public SecretKey generateKey() {
		return aes.generateKey(KEY_SIZE);
	}

	@Override
	public MultiSecretKey generateMultiKey(SecretKey... keys) {
		return new MultiSecretKey(keys);
	}

	@Override
	public void setKey(MultiSecretKey key) {
		this.key = key;
		isKeySet = true;
	}

	public void setFreeXor(boolean isFreeXor){
		this.isFreeXor = isFreeXor;
	}
	
	@Override
	public byte[] encrypt(byte[] plaintext) throws KeyNotSetException, TweakNotSetException, IllegalBlockSizeException {
		if (!isKeySet) {
			throw new KeyNotSetException();
		}
		if (!isTweakSet) {
			throw new TweakNotSetException();
		}
		// XOR all of the keys to each other.
		SecretKey[] keys = key.getKeys();
		byte[] inBytes;
		if (isFreeXor){
			//In case of free xor circuit, we multiply k0 by two. This is done by shifting k0 bits to the left.
			inBytes = shiftLeft(keys[0].getEncoded());
		} else {
			inBytes = keys[0].getEncoded();
		}
		for (int i = 1; i < keys.length; i++) {
			byte[] currKeyBytes;
			if (isFreeXor){	
				//In case of free xor circuit, we divide k1 by two. This is done by shifting k0 bits to the right.
				currKeyBytes = shiftRight(keys[i].getEncoded());
			} else {
				currKeyBytes = keys[i].getEncoded();
			}
			
			for (int byteNumber = 0; byteNumber < inBytes.length; byteNumber++) {
				inBytes[byteNumber] ^= currKeyBytes[byteNumber];
			}
		}
		// Xor the result to the tweak.
		for (int byteNumber = 0; byteNumber < inBytes.length; byteNumber++) {
			inBytes[byteNumber] ^= tweak[byteNumber];
		}
		byte[] outBytes = new byte[KEY_SIZE / 8];
		
		/*
		 * At this point inBytes contains the wire values XOR's with each other XOR'd with the tweak. 
		 * This is referred to as K in section 5.6 of "Garbling Schemes" by Bellare, Hoang and Rogaway.
		 */
		aes.computeBlock(inBytes, 0, outBytes, 0);
		
		/*
		 * XOR the output of the AES again with inBytes (i.e. K in the above cited paper) and then with the plaintext to obtain the ciphertext.
		 */
		for (int byteNumber = 0; byteNumber < outBytes.length; byteNumber++) {
			outBytes[byteNumber] ^= inBytes[byteNumber];
			outBytes[byteNumber] ^= plaintext[byteNumber];
		}

		return outBytes;
	}

	@Override
	public byte[] decrypt(byte[] ciphertext) throws KeyNotSetException, TweakNotSetException, IllegalBlockSizeException {
		if (!isKeySet) {
			throw new KeyNotSetException();
		}
		if (!isTweakSet) {
			throw new TweakNotSetException();
		}
		SecretKey[] keys = key.getKeys();
		byte[] inBytes;
		if (isFreeXor){
			inBytes = shiftLeft(keys[0].getEncoded());
		} else {
			inBytes = keys[0].getEncoded();
		}
		for (int i = 1; i < keys.length; i++) {
			byte[] currKeyBytes;
			if (isFreeXor){	
				currKeyBytes = shiftRight(keys[i].getEncoded());
			} else {
				currKeyBytes = keys[i].getEncoded();
			}
			for (int byteNumber = 0; byteNumber < inBytes.length; byteNumber++) {
				inBytes[byteNumber] ^= currKeyBytes[byteNumber];
			}
		}
		for (int byteNumber = 0; byteNumber < inBytes.length; byteNumber++) {
			inBytes[byteNumber] ^= tweak[byteNumber];
		}
		byte[] outBytes = new byte[KEY_SIZE / 8];
		/*
		 * At this point inBytes contains the wire values XOR's with each other XOR'd with the tweak. 
		 * This is referred to as K in section 5.6 of "Garbling Schemes" by Bellare, Hoang and Rogaway
		 */
		aes.computeBlock(inBytes, 0, outBytes, 0);
		/*
		 * XOR the output of the AES again with inBytes (i.e. K in the above cited paper) and then with the ciphertext to obtain the plaintext.
		 */
		for (int byteNumber = 0; byteNumber < outBytes.length; byteNumber++) {
			outBytes[byteNumber] ^= inBytes[byteNumber];
			outBytes[byteNumber] ^= ciphertext[byteNumber];
		}
		return outBytes;
	}

	/**
	 * Shifts the bits of the given array to the right.
	 * @param bytes to shift right.
	 * @return an array containing the given bytes shifted right.
	 */
	private byte[] shiftRight(byte[] bytes){
		
		ByteBuffer temp = ByteBuffer.wrap(bytes);
		LongBuffer longBuf = temp.asLongBuffer();
		int size = longBuf.capacity();
		for (int i=0; i<size; i++){
			longBuf.put(i, longBuf.get(i) >> 1);
		}
		temp.asLongBuffer().put(longBuf);
		return temp.array();
	}
	
	/**
	 * Shifts the bits of the given array to the left.
	 * @param bytes to shift left.
	 * @return an array containing the given bytes shifted left.
	 */
	private byte[] shiftLeft(byte[] bytes){
		ByteBuffer temp = ByteBuffer.wrap(bytes);
		LongBuffer longBuf = temp.asLongBuffer();
		int size = longBuf.capacity();
		for (int i=0; i<size; i++){
			longBuf.put(i, longBuf.get(i) << 1);
		}
		temp.asLongBuffer().put(longBuf);
		return temp.array();
	}
	
	@Override
	public boolean isKeySet() {
		return isKeySet;
	}

	@Override
	public void setTweak(byte[] tweak) {
		this.tweak = tweak;
		isTweakSet = true;
	}
	
	/**
	 *  Returns the block size of aes.
	 */
	@Override
	public int getCipherSize() {
		
		return aes.getBlockSize();
	} 
}
