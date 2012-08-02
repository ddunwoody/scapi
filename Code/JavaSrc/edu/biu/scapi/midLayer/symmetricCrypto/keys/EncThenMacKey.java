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
/**
 * 
 */
package edu.biu.scapi.midLayer.symmetricCrypto.keys;

import javax.crypto.SecretKey;

/**
 * This class is a simple holder for a pair of secret keys, one used for encryption and the other one for authentication.
 * Yet, it is also a type of AuthEncKey and for extension a type of Secret key. Therefore, it can be passed to the
 * init functions of classes implementing the SymmetricEnc interface. Since ScEncryptThenMac is a type of SymmetricEnc,
 * it needs a key of type SecretKey to be passed in its init functions, but also it has to make sure that two distinct
 * keys have been passed, one for encryption and one for authentication. This can be achieved using an instance of this class.
 *    
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class EncThenMacKey implements AuthEncKey {
	
	private static final long serialVersionUID = -5448970400092157445L;

	private SecretKey encKey= null;
	
	private SecretKey macKey = null;
	
	public EncThenMacKey(SecretKey encKey, SecretKey macKey){
		this.encKey = encKey;
		this.macKey = macKey;
	}
	/**
	 * This function returns the secret key that will be used for encryption.
	 * @return the encryption SecretKey
	 */
	public SecretKey getEncryptionKey(){
		return encKey;
	}

	/**
	 * This function returns the secret key that will be used for authentication.
	 * @return the authentication SecretKey
	 */
	public SecretKey getMacKey() {
		return macKey;
	}
	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		
		return "EncThenMac";
	}

	/**
	 * This operation is not supported for this type of key. Instead,get the encoded MAC key, or the encoded encryption key separately.
	 * @throws  UnsupportedOperationException always throws this exception.
	 */
	@Override
	public byte[] getEncoded() {
		throw new UnsupportedOperationException("Get the encoded MAC key, or the encoded encryption key separately");
	}

	/**
	 * This operation is not supported for this type of key, since there is no format defined for algorithm Encrypt-Then-MAC.
	 * @throws  UnsupportedOperationException always throws this exception.
	 */
	@Override
	public String getFormat() {
		throw new UnsupportedOperationException("No format defined for algorithm Encrypt-Then-MAC");
	}

}
