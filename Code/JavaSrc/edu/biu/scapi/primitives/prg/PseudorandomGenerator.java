package edu.biu.scapi.primitives.prg;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;

/** 
 * General interface of pseudorandom generator. Every concrete class in this family should implement this interface. <p>
 * 
 * A pseudorandom generator (PRG) is a deterministic algorithm that takes a “short” uniformly distributed string, 
 * known as the seed, and outputs a longer string that cannot be efficiently distinguished from a uniformly 
 * distributed string of that length.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
  */
public interface PseudorandomGenerator {
	
	/**
	 * Sets the secret key for this prg.
	 * The key can be changed at any time. 
	 * @param secretKey secret key
	 * @throws InvalidKeyException 
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException;
	
	/**
	 * An object trying to use an instance of prg needs to check if it has already been initialized.
	 * @return true if the object was initialized by calling the function setKey.
	 */
	public boolean isKeySet();

	/** 
	 * @return the algorithm name. For example - RC4
	 */
	public String getAlgorithmName();
	
	/**
	 * Generates a secret key to initialize this prg object.
	 * @param keyParams algorithmParameterSpec contains the required parameters for the key generation
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates a secret key to initialize this prg object.
	 * @param keySize is the required secret key size in bits 
	 * @return the generated secret key 
	 */
	public SecretKey generateKey(int keySize);

	/**
	 * Streams the prg bytes.
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outlen - the required output length
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset, int outlen) ;
	
	

	
}