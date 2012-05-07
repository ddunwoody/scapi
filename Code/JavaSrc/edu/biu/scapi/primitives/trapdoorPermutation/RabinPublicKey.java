package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.PublicKey;


/**
 * Interface for Rabin public key.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public interface RabinPublicKey  extends RabinKey, PublicKey{
	
	/**
	 * @return BigInteger - QuadraticResidueModPrime1 (r)
	 */
	public BigInteger getQuadraticResidueModPrime1();
	
	/**
	 * @return BigInteger - QuadraticResidueModPrime2 (s)
	 */
	public BigInteger getQuadraticResidueModPrime2();
}
