package edu.biu.scapi.primitives.trapdoorPermutation;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Interface for RabinParameterSpec
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class RabinKeyGenParameterSpec implements AlgorithmParameterSpec{
	int keySize;
	
	/**
	 * Constructor that set the keybits
	 * @param keySize
	 */
	public RabinKeyGenParameterSpec(int keySize) {
		if (keySize<16){
			throw new IllegalArgumentException("Rabin Key size should be greater than 15");
		}
		this.keySize = keySize;
	}
	
	/**
	 * @return int - The key bits size
	 */
	public int getKeySize() {
		return keySize;
	}
}
