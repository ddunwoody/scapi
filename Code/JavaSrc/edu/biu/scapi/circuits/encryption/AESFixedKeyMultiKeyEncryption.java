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

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.ciphertext.ByteArraySymCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;

/**
 * See <i>Garbling * Schemes </i> by Mihir Bellare, Viet Tung Hoang, and Phillip
 * Rogaway Section 5.6 for a full description of thus encryption scheme. This
 * encryption scheme uses AES with a fixed key and thus has the benefit of not
 * needing to repeatedly perform the costly setKey procedure for AES.
 * <p>
 * This encryption scheme works by XORing all of the wire values(i.e. keys) to
 * one another and then XORing this to the tweak. This value is denoted by K. We
 * then call AES with the fixed key on K/ We then COR the result of that to K
 * and then to the plaintext to encrypt.
 * 
 * @author Steven Goldfeder
 * 
 */
public class AESFixedKeyMultiKeyEncryption implements MultiKeyEncryptionScheme {

	/**
	 * The number of bits in the key. It is currently set to 128, and the
	 * {@code FIXED_KEY} field is this size
	 */
	static final int KEY_SIZE = 128; // key size in bits
	/**
	 * A 128 bit key that we generated once and hardcoded in.
	 */
	static final SecretKey FIXED_KEY = new SecretKeySpec(new byte[] { -13, 29,
			-20, 98, -96, -51, -86, -82, 9, 49, -26, 92, -22, 50, -100, 36 }, "");
	PseudorandomFunction aes;
	/**
	 * The key here is not the key to the AES, but rather the key to this
	 * encryption scheme. See Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway
	 * Section 5.6 or see the {@link #encrypt(ByteArrayPlaintext)}/
	 * {@link #decrypt(ByteArraySymCiphertext)} methods below to see how these
	 * keys are used in encrpytion/decryption
	 */
	MultiSecretKey key;
	/**
	 * For the tweak, we use the gate number followed by the signal bits for each
	 * of the input wires.
	 */
	byte[] tweak;
	/**
	 * {@code boolean} flag that is {@code true} of the key has been set,
	 * {@code false} otherwise
	 */
	boolean isKeySet = false;
	/**
	 * {@code boolean} flag that is {@code true} of the tweak has been set,
	 * {@code false} otherwise
	 */
	boolean isTweakSet = false;

	public AESFixedKeyMultiKeyEncryption() throws FactoriesException, InvalidKeyException {
		// aes = new BcAES();
		aes = new CryptoPpAES();
		aes.setKey(FIXED_KEY);
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
	public ByteArraySymCiphertext encrypt(ByteArrayPlaintext plaintext) throws KeyNotSetException, TweakNotSetException, IllegalBlockSizeException {
		if (!isKeySet) {
			throw new KeyNotSetException();
		}
		if (!isTweakSet) {
			throw new TweakNotSetException();
		}
		// XOR all of the keys to each other
		SecretKey[] keys = key.getKeys();
		byte[] inBytes = keys[0].getEncoded();
		for (int i = 1; i < keys.length; i++) {
			byte[] currKeyBytes = keys[i].getEncoded();
			for (int byteNumber = 0; byteNumber < inBytes.length; byteNumber++) {
				inBytes[byteNumber] ^= currKeyBytes[byteNumber];
			}
		}
		// xor the result to the tweak
		for (int byteNumber = 0; byteNumber < inBytes.length; byteNumber++) {
			inBytes[byteNumber] ^= tweak[byteNumber];
		}
		byte[] outBytes = new byte[KEY_SIZE / 8];
		/*
		 * at this point inBytes contains the wire values XOR's with each other
		 * XOR'd with the tweak. This is referred to as K in section 5.6 of
		 * "Garbling Schemes" by Bellare, Hoang and Rogaway
		 */
		aes.computeBlock(inBytes, 0, outBytes, 0);
		byte[] plaintextBytes = plaintext.getText();
		/*
		 * We now XOR the output of the AES again with inBytes(i.e. K in the above
		 * cited paper) and then with the plaintext to obtain the ciphertext
		 */
		for (int byteNumber = 0; byteNumber < outBytes.length; byteNumber++) {
			outBytes[byteNumber] ^= inBytes[byteNumber];
			outBytes[byteNumber] ^= plaintextBytes[byteNumber];
		}

		return new ByteArraySymCiphertext(outBytes);
	}

	@Override
	public ByteArrayPlaintext decrypt(ByteArraySymCiphertext ciphertext) throws KeyNotSetException, TweakNotSetException, IllegalBlockSizeException {
		if (!isKeySet) {
			throw new KeyNotSetException();
		}
		if (!isTweakSet) {
			throw new TweakNotSetException();
		}
		SecretKey[] keys = key.getKeys();
		byte[] inBytes = keys[0].getEncoded();
		for (int i = 1; i < keys.length; i++) {
			byte[] currKeyBytes = keys[i].getEncoded();
			for (int byteNumber = 0; byteNumber < inBytes.length; byteNumber++) {
				inBytes[byteNumber] ^= currKeyBytes[byteNumber];
			}
		}
		for (int byteNumber = 0; byteNumber < inBytes.length; byteNumber++) {
			inBytes[byteNumber] ^= tweak[byteNumber];
		}
		byte[] outBytes = new byte[KEY_SIZE / 8];
		/*
		 * at this point inBytes contains the wire values XOR's with each other
		 * XOR'd with the tweak. This is referred to as K in section 5.6 of
		 * "Garbling Schemes" by Bellare, Hoang and Rogaway
		 */
		aes.computeBlock(inBytes, 0, outBytes, 0);
		/*
		 * We now XOR the output of the AES again with inBytes(i.e. K in the above
		 * cited paper) and then with the ciphertext to obtain the plaintext
		 */
		for (int byteNumber = 0; byteNumber < outBytes.length; byteNumber++) {
			outBytes[byteNumber] ^= inBytes[byteNumber];
			outBytes[byteNumber] ^= ciphertext.getBytes()[byteNumber];
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
