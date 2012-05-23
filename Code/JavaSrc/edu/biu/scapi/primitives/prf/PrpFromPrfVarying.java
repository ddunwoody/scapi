package edu.biu.scapi.primitives.prf;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

/** 
 * This class implements some common functionality of PrpVaryingIOLength by having an instance of prfVaryingIOLength.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public abstract class PrpFromPrfVarying implements PrpVaryingIOLength {
	
	protected PrfVaryingIOLength prfVaryingIOLength; // the underlying prf
	
	/**
	 * Initializes this PrpFromPrfVarying with secret key
	 * @param secretKey the secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException {
		//initializes the underlying prf with the given secret key
		prfVaryingIOLength.setKey(secretKey);
	}

	public boolean isKeySet(){
		// call the underlying prf isInitialized function and return the result
		return prfVaryingIOLength.isKeySet();
	}
	
	

	/** 
	 * This function is suitable for block ciphers where the input/output length is known in advance.
	 * In this case, both input and output variables are varying so this function should not be called. Throws an exception.
	 * 
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		
		throw new IllegalBlockSizeException("to use this prp, call the computeBlock function that specifies the block size length");
	}

	/** 
	 * Computes the function using the secret key. <p>
	 * 
	 * This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input and output length.
	 * Since this is a prp, both input and output variables should be equal and there is no need to send them both, so this function should not be called. 
	 * If the user still wants to use this function, the specified arguments <code>inLen<code> and <code>outLen<code> should be the same, otherwise, throws an exception.
	 * 
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param inLen the length of the input array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to put the result from
	 * @param outLen the length of the output array
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen)	throws IllegalBlockSizeException {
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		// checks that the offsets and lengths are correct 
		if ((inOff > inBytes.length) || (inOff+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+outLen > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//if the input and output lengths are equal, call the computeBlock which takes just one length argument
		if (inLen == outLen){
			computeBlock(inBytes, inOff, inLen, outBytes, outOff);
		}
		else throw new IllegalBlockSizeException("input and output lengths should be equal");
		
	}

	/**
	 * This function is suitable for block ciphers where the input/output length is known in advance.
	 * In this case, both input and output variables are varying so this function should not be called. Throws an exception.
	 * 
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,	int outOff) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("secret key isn't set");
		}
		throw new IllegalBlockSizeException("to use this prp, call the invertBlock function which specify the block size length");
		
	}

	/**
	 * Generate a SecretKey suitable for a Pseudo random permutation obtained from a Varying Prf.
	 * @param keyParams an instance of a class implementing the AlgorithmParameterSpec interface 
	 * 					that holds the necessary parameters to generate the key.
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException if keyParams is not an instance of relevant Parameter Spec.
	 */
	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		return prfVaryingIOLength.generateKey(keyParams);
	}

	/**
	 * Generate a SecretKey suitable for a Pseudo random permutation obtained from a Varying Prf.
	 * @param keySize bit-length of required Secret Key
	 * @return the generated secret key
	 */
	@Override
	public SecretKey generateKey(int keySize) {
		return prfVaryingIOLength.generateKey(keySize);
	}
	
	
}