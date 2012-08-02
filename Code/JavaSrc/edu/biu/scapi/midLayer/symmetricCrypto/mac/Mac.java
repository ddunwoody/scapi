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
package edu.biu.scapi.midLayer.symmetricCrypto.mac;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.SecretKey;


/**
 * General interface for Mac. Every class in this family must implement this interface. <p>
 * 
 * In cryptography, a message authentication code (often MAC) is a short piece of information used to authenticate a message.
 * 
 * A MAC algorithm, accepts as input a secret key and an arbitrary-length message to be authenticated, 
 * and outputs a tag. The tag value protects both a message's data integrity as well as its authenticity, by allowing verifiers 
 * (who also possess the secret key) to detect any changes to the message content.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface Mac {
	
	/**
	 * Sets the secret key for this mac.
	 * The key can be changed at any time. 
	 * @param secretKey secret key
	 * @throws InvalidKeyException if the given key does not match this MAC algorithm.
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException;
	
	/**
	 * An object trying to use an instance of mac needs to check if it has already been initialized.
	 * @return true if the object was initialized by calling the function setKey.
	 */
	public boolean isKeySet();
	
	
	/**
	 * Returns the name of this mac algorithm.
	 * @return the name of this mac algorithm.
	 */
	public String getAlgorithmName();
	
	/**
	 * Returns the input block size in bytes.
	 * @return the input block size.
	 */
	public int getMacSize();
	
	/**
	 * Generates a secret key to initialize this mac object.
	 * @param keyParams algorithmParameterSpec contains  parameters for the key generation of this mac algorithm.
	 * @return the generated secret key.
	 * @throws InvalidParameterSpecException if the given keyParams does not match this mac algoithm.
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates a secret key to initialize this mac object.
	 * @param keySize is the required secret key size in bits.
	 * @return the generated secret key.
	 */
	public SecretKey generateKey(int keySize);
	
	/**
	 * Computes the mac operation on the given msg and return the calculated tag.
	 * @param msg the message to operate the mac on.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLen the length of the message in bytes.
	 * @return byte[] the return tag from the mac operation.
	 */
	public byte[] mac(byte[] msg, int offset, int msgLen);
	
	/**
	 * Verifies that the given tag is valid for the given message.
	 * @param msg the message to compute the mac on to verify the tag.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLength the length of the message in bytes.
	 * @param tag the tag to verify.
	 * @return true if the tag is the result of computing mac on the message. false, otherwise.
	 */
	public boolean verify(byte[] msg, int offset, int msgLength, byte[] tag);
	
	/**
	 * Adds the byte array to the existing message to mac.
	 * @param msg the message to add.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLen the length of the message in bytes.
	 */
	public void update(byte[] msg, int offset, int msgLen);
	
	/**
	 * Completes the mac computation and puts the result tag in the tag array.
	 * @param msg the end of the message to mac.
	 * @param offset the offset within the message array to take the bytes from.
	 * @param msgLength the length of the message in bytes.
	 * @return the result tag from the mac operation.
	 */
	public byte[] doFinal(byte[] msg, int offset, int msgLength);
}
