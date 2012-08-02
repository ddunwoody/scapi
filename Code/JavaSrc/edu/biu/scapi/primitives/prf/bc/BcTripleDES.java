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
package edu.biu.scapi.primitives.prf.bc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.DESedeEngine;

import edu.biu.scapi.primitives.prf.TripleDES;

/**
 * Concrete class of prf family for Triple-DES. This class wraps the implementation of Bouncy castle.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcTripleDES extends BcPRP implements TripleDES{

	/**
	 * Passes the DesedeEngine of BC to the abstract super class
	 */
	public BcTripleDES() {
		
		super(new DESedeEngine());
	}
	
	/**
	 * Receives random object to use.
	 * Passes it and the DesedeEngine of BC to the abstract super class.
	 * @param random SecureRandom to use
	 */
	public BcTripleDES(SecureRandom random) {
		
		super(new DESedeEngine(), random);
	}
	
	/**
	 * Receives name of random algorithm to use.
	 * Passes it and the DesedeEngine of BC to the abstract super class.
	 * @param randNumGenAlg random algorithm to use
	 */
	public BcTripleDES(String randNumGenAlg) throws NoSuchAlgorithmException {
		
		super(new DESedeEngine(), SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * initializes this Triple-DES with secret key.
	 * @param secretKey the secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//TripleDes key size should be 128/192 bits 
		if(len!=16 && len!=24){
			throw new InvalidKeyException("TripleDes key size should be 128/192 bits long");
		}
		super.setKey(secretKey);
	}

	/**
	 * This function should not be used to generate a key for TripleDes and it throws UnsupportedOperationException
	 * @param keyParams algorithmParameterSpec contains the required secret key size in bits 
	 * @return the generated secret key
	 * @throws UnsupportedOperationException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException{
		throw new UnsupportedOperationException("To generate a key for this prf object use the generateKey(int keySize) function");
	}
}
