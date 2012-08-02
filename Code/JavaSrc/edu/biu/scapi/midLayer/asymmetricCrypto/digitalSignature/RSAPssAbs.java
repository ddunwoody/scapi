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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * Abstract class for RSA PSS signature scheme. This class implements some common functionality of RSA signature scheme.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class RSAPssAbs implements RSABasedSignature{

	protected SecureRandom random;		//Source of randomness
	protected boolean isKeySet;
	protected RSAPublicKey publicKey;
	
	@Override
	public boolean isKeySet() {
		return isKeySet;
	}
	
	/**
	 * Returns the PublicKey of this RSA encryption scheme.
	 * This function should not be use to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the RSAPublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey(){
		if (!isKeySet()){
			throw new IllegalStateException("no PublicKey was set");
		}
		
		return publicKey;
	}
	
	/**
	 * @return this signature scheme name - "RSA/PSS"
	 */
	@Override
	public String getAlgorithmName() {
		
		return "RSA/PSS";
	}
	
	/**
	 * Generate an RSA key pair using the given parameters.
	 * @param keyParams RSAKeyGenParameterSpec.
	 * @return KeyPair contains keys for this RSAPss object.
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAKeyGenParameterSpec.
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams)
			throws InvalidParameterSpecException {
		
		try {
			//Generates keys using the KeyPairGenerator.
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keyParams, random);
			return generator.generateKeyPair(); 
		} catch(InvalidAlgorithmParameterException e){
			//Throws the same exception with different message.
			throw new InvalidParameterSpecException("keyParams should be instance of RSAKeyGenParameterSpec");
		} catch (NoSuchAlgorithmException e) {
			//Shouldn't occur since RSA is a valid algorithm.
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * This function is not supported in this class. 
	 * Use generateKey(AlgorithmParameterSpec keyParams) instead.
	 * @throws UnsupportedOperationException
	 */
	@Override
	public KeyPair generateKey() {
		throw new UnsupportedOperationException("To generate keys for this RSAPss use the other generateKey function with RSAKeyGenParameterSpec");
	}

}
