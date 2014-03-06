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

import java.security.InvalidKeyException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.exceptions.TweakNotSetException;

/**
 * A general interface for creating multiple key encryption schemes. <p>
 * When constructing a garbled circuit, an encryption scheme must be specified. 
 * The Garbled circuit will use the specified scheme to encrypt each gate. <p>
 * 
 * See <i> Garbling Schemes</i> by Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway. In this paper, the authors present the idea of a
 * Garbling Scheme--i.e. the notion to treat Garbling Schemes as cryptographic primitive. In the paper, they present a number of 
 * different efficient garbling schemes.<p>
 * 
 * We have implemented a number of the schemes that they mentioned, and any other garbling scheme can easily be implemented and used 
 * anywhere in our code as long as they implement this interface. 
 * 
 * @author Steven Goldfeder
 * 
 */
public interface MultiKeyEncryptionScheme {

	/**
	 * This method generates a <b>single</b> {@codeSecretKey} NOT a {@code MultiSecretKey}. <p>
	 * This is necessary since the user will often need to generate single keys first and then combine them to a single 
	 * {@code MultiSecretKey}.<p>
	 * Consider the following problem: Say we want to garble and compute a gate in Yao's protocol. 
	 * Consider a 2 input gate. Each input Wire will have two possible garbled values--corresponding to a 0 value and a 1 value. 
	 * These values are <@code SecretKey}s <b>NOT</b? {@code MultiSecretKey}s. When we encrypt the truth table, we combine the single
	 * keys to create {@code MultiSecretKey}s. So, if we want to encrypt the 0-0 entry of the truth table, we will take the 0 key from 
	 * each {@code GarbledWire} and combine them to a {@code MultiSecretKey} (using the {@code generateMultiKey()} method. 
	 * Then if we want to encrypt the 0-1 entry, we will use the 0-key from the first wire and the 1-key from the second wire. 
	 * We will combine these 2 keys into a single {@code MultiSecretKey} and use this to encrypt. Note that in this example,
	 * the 0-key from the first Wire is combined from 2 different {@code MultiSecretKey}s. First we combined it with the 0-key of the second
	 * wire and then we combined it with the 1-key. <p>
	 * Thus, it is necessary to have a method to generate individual keys and a separate method to combine different single keys into
	 * {@code MultiSecretKey}s. 
	 * 
	 * @return {@link SecretKey} of the specified size. One or more of these keys will be combined into a 
	 * 					{@code MultiSecretKey} to encrypt and decrypt with.
	 */
	public SecretKey generateKey();

	/**
	 * This method is provided with individual {@code SecretKey}s and combines them into a {@code MultiSecretKey} that can be used 
	 * for encryption and decryption with the {@code MultiKeyEncryptionScheme}.
	 * 
	 * @param keys The individual {@link SecretKey}s that make up the {@code MultiSecretKey}. 
	 * The {@code SecretKey} objects can be passed in an array or as individual parameters.
	 * @return a {@code MultiSecretKey} made up of the {@code SecretKey}s that were passed as parameters.
	 */
	public MultiSecretKey generateMultiKey(SecretKey... keys);

	/**
	 * Sets the key to the specified {@code MultiKeyEncryptionScheme}.<p>
	 * The key that it is currently set to, will be used for encryption and decryption until {@code setKey()} is called again.
	 * 
	 * @param key The {@code MultiSecretKey} to be used for encryption and decryption.
	 */
	public void setKey(MultiSecretKey key);

	/**
	 * See <i> Garbling Schemes</i> by Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway. <p>
	 * Some encryption schemes use a tweak and instead of encrypting directly the entry of the plaintext, encrypt the tweak 
	 * and then XOR the result with the plaintext. <p>
	 * Some encryption schemes do not make use of a tweak, in which case calls to set the tweak have no effect.
	 * If you are implementing an encryption scheme that does not use a tweak, just leave the body of this method blank.
	 * 
	 * @param tweak The tweak to be used for this encryption scheme.
	 */
	public void setTweak(byte[] tweak);
	
	/**
	 * This method used the individual {@code SecretKey}s that make up the {@code MultiSecretKey} to encrypt the plaintext.
	 * 
	 * @param plaintext The plaintext to be encrypted.
	 * @return the ciphertext--i.e. the plainetext encrypted with the currently set key.
	 * @throws KeyNotSetException
	 * @throws TweakNotSetException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */

	public byte[] encrypt(byte[] plaintext) throws KeyNotSetException, TweakNotSetException, IllegalBlockSizeException, PlaintextTooLongException, InvalidKeyException;

	/**
	 * Decrypts the ciphertext.
	 * @param ciphertext The ciphertext to be decrypted
	 * @return the plaintext--i.e. the ciphertext decrypted with the currently set key.
	 * @throws CiphertextTooLongException
	 * @throws KeyNotSetException
	 * @throws TweakNotSetException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 */

	public byte[] decrypt(byte[] ciphertext) throws CiphertextTooLongException, KeyNotSetException, TweakNotSetException, InvalidKeyException, IllegalBlockSizeException;

	/**
	 * Checks if the key for this {@code MultiKeyEncryptionScheme} has been set.<P>
	 * Returning {@code true} if it has been and {@code false} if it has not been. <P>
	 * Before encrypting and decrypting, the key must be set.
	 * 
	 * @return {@code true} if the key has been set, {@code false} otherwise.
	 */
	public boolean isKeySet();
	
	/**
	 * Returns the size of the ciphertext.
	 */
	public int getCipherSize();

}
