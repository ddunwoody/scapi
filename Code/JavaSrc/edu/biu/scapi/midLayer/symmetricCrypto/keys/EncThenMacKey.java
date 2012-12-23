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
