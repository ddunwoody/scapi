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
package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.midLayer.signature.Signature;

/**
 * General interface for digital signatures. Each class of this family must implement this interface. <p>
 * 
 * A digital signature is a mathematical scheme for demonstrating the authenticity of a digital message or document. 
 * A valid digital signature gives a recipient reason to believe that the message was created by a known sender, 
 * and that it was not altered in transit.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DigitalSignature {

	
	/**
	 * Sets this digital signature with public key and private key.
	 * @param publicKey
	 * @param privateKey
	 * @throws InvalidKeyException if the given keys do not match this signature scheme.
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey)throws InvalidKeyException;
	
	/**
	 * Sets this digital signature with a public key.<p> 
	 * In this case the signature object can be used only for verification.
	 * @param publicKey
	 * @throws InvalidKeyException if the given key does not match his signature scheme.
	 */
	public void setKey(PublicKey publicKey)throws InvalidKeyException;
	
	/**
	 * Checks if this digital signature object has been given a key already.<p> 
	 * @return <code>true<code> if the object has been given a key;
	 * 		   <code>false</code> otherwise.
	 */
	public boolean isKeySet();
	
	/**
	 * Returns the PublicKey of this signature scheme. <p>
	 * This function should not be use to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the PublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey();
	
	/**
	 * @return the name of this digital signature scheme.
	 */
	public String getAlgorithmName();
	
	/**
	 * Signs the given message
	 * @param msg the byte array to sign.
	 * @param offset the place in the msg to take the bytes from.
	 * @param length the length of the msg.
	 * @return the signatures from the msg signing.
	 * @throws KeyException if PrivateKey is not set.
	 * @throws ArrayIndexOutOfBoundsException if the given offset and length are wrong for the given message.
	 */
	public Signature sign(byte[] msg, int offset, int length) throws KeyException;
	
	/**
	 * Verifies the given signature.
	 * @param signature to verify
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return true if the signature is valid. false, otherwise.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Signature does not match this signature scheme.
	 * @throws ArrayIndexOutOfBoundsException if the given offset and length are wrong for the given message.
	 */
	public boolean verify(Signature signature, byte[] msg, int offset, int length);

	/**
	 * Generates public and private keys for this digital signature.
	 * @param keyParams hold the required key parameters
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException if the given keyParams does not match this signature scheme.
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates public and private keys for this digital signature.
	 * @return KeyPair holding the public and private keys 
	 */
	public KeyPair generateKey();
}
