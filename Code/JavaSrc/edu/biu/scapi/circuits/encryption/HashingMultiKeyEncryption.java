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

import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.ciphertext.ByteArraySymCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
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
	CryptographicHash hash;

	/**
	 * @throws FactoriesException
	 * @throws InvalidKeySizeException 
	 */
	public HashingMultiKeyEncryption(int keySize) throws FactoriesException, InvalidKeySizeException {
		if(keySize% 8 != 0){
			throw new InvalidKeySizeException();
		}
		this.keySize = keySize;
		hash = CryptographicHashFactory.getInstance().getObject("SHA-1");
		random = new SecureRandom();
		isKeySet = false;
	}

	/**
	 * 
	 */
	public HashingMultiKeyEncryption() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public ByteArraySymCiphertext encrypt(ByteArrayPlaintext plaintext)
			throws KeyNotSetException, PlaintextTooLongException {
		byte[] ptBytes = plaintext.getText();
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
		int offset = output.length - ptBytes.length;
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

			byte[] temp = new byte[ptBytes.length];
			for (int i = 0; i < temp.length; i++) {
				temp[i] = output[i + offset];
			}
			output = temp;
		}
		for (int i = 0; i < output.length; i++) {
			output[i] ^= ptBytes[i];
		}
		return new ByteArraySymCiphertext(output);
	}

	@Override
	public ByteArrayPlaintext decrypt(ByteArraySymCiphertext ciphertext)
			throws KeyNotSetException, CiphertextTooLongException {
		if (!isKeySet()) {
			throw new KeyNotSetException();
		}
		// see comments to encrypt method to understand the encryption/decryption
		byte[] ctBytes = ciphertext.getBytes();
		for (SecretKey k : key.getKeys()) {
			hash.update(k.getEncoded(), 0, keySize / 8);
		}
		byte[] output = new byte[20];
		hash.hashFinal(output, 0);
		int offset = output.length - ctBytes.length;
		if (offset < 0) {
			throw new CiphertextTooLongException();
		}
		if (offset > 0) {
			byte[] temp = new byte[ctBytes.length];
			for (int i = 0; i < temp.length; i++) {
				temp[i] = output[i + offset];
			}
			output = temp;
		}
		for (int i = 0; i < output.length; i++) {
			output[i] ^= ctBytes[i];
		}
		return new ByteArrayPlaintext(output);
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
}
