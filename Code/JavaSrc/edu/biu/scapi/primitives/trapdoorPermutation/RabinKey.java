package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.Key;

/**
 * General interface for Rabin Keys
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public interface RabinKey extends Key{
	
	/**
	 * @return BigInteger - the modulus
	 */
	public BigInteger getModulus();
}
