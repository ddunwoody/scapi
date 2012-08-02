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
package edu.biu.scapi.primitives.prf;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

/** 
 * This class implements some common functionality of varying input and output length prf classes.
 * 
 * PrfVaryingFromPrfVaryingInput is a pseudorandom function with varying input/output lengths, based on HMAC or any other implementation 
 * of PrfVaryingInputLength. We take the interpretation that there is essentially a different random function for every output length. 
 * This can be modeled by applying the random function to the input and the required output length (given as input to the oracle). 
 * The pseudorandom function must then be indistinguishable from this.
 * We use PrfVaryingInputLength for this construction because the input length can already be varying; this makes the construction more simple and efficient. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 * 
 */
public abstract class PrfVaryingFromPrfVaryingInput implements PrfVaryingIOLength {
	
	protected PrfVaryingInputLength prfVaryingInputLength; //the underlying prf varying input
	
	
	/** 
	 * Initializes this PrfVaryingFromPrfVaryingInput with the secret key.
	 * @param secretKey secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {

		prfVaryingInputLength.setKey(secretKey); //initializes the underlying prf
		
	}

	/**
	 * Check that the Secret Key for this instance has been set
	 * @return true if key had been set<p>
	 * 			false, otherwise.
	 */
	public boolean isKeySet(){
		return prfVaryingInputLength.isKeySet();
	}
	

	/** 
	 * Since both input and output variables are varying this function should not be called.
	 * @throws UnsupportedOperationException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException{
		throw new UnsupportedOperationException("Only compute that gets lengths of I/O should be called for Varying Prf");
	}



	/** 
	 * Since both input and output variables are varying this function should not be call.
	 * @throws UnsupportedOperationException
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff) throws IllegalBlockSizeException{
		throw new UnsupportedOperationException("Only compute that gets lengths of I/O should be called for Varying Prf");
	}
	
	/**
	 * Generate a SecretKey suitable for a Pseudo random permutation obtained from a Varying Prf.
	 * @param keyParams an instance of a class implementing the AlgorithmParameterSpec interface 
	 * 					that holds the necessary parameters to generate the key.
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException if keyParams is not an instance of relevant Parameter Spec.
	 */
	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keyParams)
			throws InvalidParameterSpecException {
		return prfVaryingInputLength.generateKey(keyParams);
	}

	/**
	 * Generate a SecretKey suitable for a Pseudo random permutation obtained from a Varying Prf.
	 * @param keySize bit-length of required Secret Key
	 * @return the generated secret key
	 */
	@Override
	public SecretKey generateKey(int keySize) {
		return prfVaryingInputLength.generateKey(keySize);
	}

}
