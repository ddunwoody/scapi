/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.circuits.encryption;

import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.garbledCircuit.MinimizeAESSetKeyGarbledBooleanCircuit;
import edu.biu.scapi.midLayer.ciphertext.ByteArraySymCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;

/**
 * This is a semi-classical double encryption scheme in which we use a PRF(
 * here, we use AES) twice on each value with different keys to double encrypt.
 * In this implementation though, we deviate slightly from the classical method
 * by using the PRF on a tweak rather than on the value itself. See <i>Garbling
 * Schemes </i> by Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway Section
 * 5.6. This implementation follows their second suggestion in section .6(the
 * second paragraph starting with a dash '-' ).
 * <p>
 * Note that this encryption scheme does not minimize the number of AES set key
 * operations. See {@link MinimizeAESSetKeyGarbledBooleanCircuit} and
 * {@code MinimizeAESSetKeyGarbledGate} for a circuit and gate that do that as
 * well as a discussion of why a separate circuit was necessary to accomplish
 * this.
 * <p>
 * This encryption scheme encrypts by setting each key from the
 * {@code MultiSecretKey} as the AES key and then calling AES on the tweak. We
 * XOR these to each other and then XOR the result to the plaintext.
 * 
 * 
 * @author Steven Goldfeder
 * 
 */
public class AES128MultiKeyEncryption implements MultiKeyEncryptionScheme {

	/**
	 * Key size in bits
	 */
	static final int KEY_SIZE = 128;
	/**
	 * The key to encrypt on. In this scheme each of the individual
	 * {@code SecretKey}s that make up the {@code MultiSecretKey} will be set as
	 * the key to AES
	 */
	MultiSecretKey key;
	SecureRandom random;
	boolean isKeySet = false;
	PseudorandomFunction aes;
	byte[] tweak;
	boolean isTweakSet = false;

	public AES128MultiKeyEncryption() {
		aes = new CryptoPpAES();
		random = new SecureRandom();
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

	@Override
	public ByteArraySymCiphertext encrypt(ByteArrayPlaintext plaintext) throws KeyNotSetException, TweakNotSetException, InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException {
		if (!isKeySet) {
			throw new KeyNotSetException();
		}
		if (!isTweakSet) {
			throw new TweakNotSetException();
		}
		/*
		 * divide by 8 since the key size is specified in bits and we are using a
		 * byte array
		 */
		if (plaintext.getText().length > KEY_SIZE / 8) {
			throw new PlaintextTooLongException();
		}
		int numberOfKeys = key.numberOfKeys();
		SecretKey[] keys = key.getKeys();
		byte[] outBytes = new byte[KEY_SIZE / 8];
		byte[] temp = new byte[KEY_SIZE / 8];
		/*
		 * we set each key from the MultiSecretKey as the aes key and use it to
		 * encrypt the tweak. We XOR these to each other and then XOR the result to
		 * the plaintext.
		 */
		for (int i = 0; i < numberOfKeys; i++) {
			aes.setKey(keys[i]);
			aes.computeBlock(tweak, 0, temp, 0);
			for (int currentByte = 0; currentByte < outBytes.length; currentByte++) {
				/*
				 * the array is initially populated with 0's an thus on the first
				 * iteration, the XOR has the effect of just setting it to the value it
				 * is being XORd to since n XOR 0 = n
				 */
				outBytes[currentByte] ^= temp[currentByte];
			}
		}
		byte[] plaintextBytes = plaintext.getText();
		for (int currentByte = 0; currentByte < outBytes.length; currentByte++) {
			outBytes[currentByte] ^= plaintextBytes[currentByte];
		}
		return new ByteArraySymCiphertext(outBytes);

	}

	@Override
	public ByteArrayPlaintext decrypt(ByteArraySymCiphertext ciphertext) throws CiphertextTooLongException, KeyNotSetException, TweakNotSetException, InvalidKeyException, IllegalBlockSizeException {
		if (!isKeySet) {
			throw new KeyNotSetException();
		}
		if (!isTweakSet) {
			throw new TweakNotSetException();
		}
		/*
		 * divide by 8 since the key size is specified in bits and we are using a
		 * byte array
		 */
		if (ciphertext.getBytes().length > KEY_SIZE / 8) {
			throw new CiphertextTooLongException();
		}
		int numberOfKeys = key.numberOfKeys();
		SecretKey[] keys = key.getKeys();
		aes.setKey(keys[0]);
		byte[] outBytes = new byte[KEY_SIZE / 8];
		/*
		 * We encrypt with the 0th key first(outside of the loop) so that outBytes
		 * is given an initial value. Then, for the remaining keys, we use aes in
		 * the loop and XOR the result to outBytes
		 */
		byte[] temp = new byte[KEY_SIZE / 8];
		aes.computeBlock(tweak, 0, outBytes, 0);
		for (int i = 1; i < numberOfKeys; i++) {
			aes.setKey(keys[i]);
			aes.computeBlock(tweak, 0, temp, 0);
			// XORing the result to outBytes
			for (int currentByte = 0; currentByte < outBytes.length; currentByte++) {
				outBytes[currentByte] ^= temp[currentByte];
			}
		}
		// we now XOR outbytes to the ciphertext to get the plaintext
		byte[] ciphertextBytes = ciphertext.getBytes();
		for (int currentByte = 0; currentByte < outBytes.length; currentByte++) {
			outBytes[currentByte] ^= ciphertextBytes[currentByte];
		}
		return new ByteArrayPlaintext(outBytes);
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

}
