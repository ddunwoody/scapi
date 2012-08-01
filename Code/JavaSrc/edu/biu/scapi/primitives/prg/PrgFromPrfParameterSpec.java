package edu.biu.scapi.primitives.prg;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameters for PrgFromPrf key generation.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class PrgFromPrfParameterSpec implements AlgorithmParameterSpec{

	private byte[] entropySource;	// Random bit sequence.=
	private int prfKeySize;			// Prf key size in bits.
	
	/**
	 * Constructor that gets random bit sequence, kdf key size in bits and prf key size in bits and sets them.
	 * @param entropySource random bit sequence.
	 * @param kdfKeySize kdf key size in bits
	 * @param prfKeySize prf key size in bits.
	 */
	public PrgFromPrfParameterSpec(byte[] entropySource, int prfKeySize){
		this.entropySource = entropySource;
		this.prfKeySize = prfKeySize;
	}
	
	public byte[] getEntropySource(){
		return entropySource;
	}
	
	
	public int getPrfKeySize(){
		return prfKeySize;
	}
}
