package edu.biu.scapi.primitives.prf;

import java.security.InvalidKeyException;

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

	public boolean isKeySet(){
		return prfVaryingInputLength.isKeySet();
	}
	

	/** 
	 * Since both input and output variables are varying this function should not be call. Throws an exception.
	 * 
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */

	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		
		throw new IllegalBlockSizeException("Input and output sizes are not specified");
		
	}



	/** 
	 * Since both input and output variables are varying this function should not be call. Throws an exception.
	 * 
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff) throws IllegalBlockSizeException{
		
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		
		throw new IllegalBlockSizeException("Output size is not specified");
		
	}

}