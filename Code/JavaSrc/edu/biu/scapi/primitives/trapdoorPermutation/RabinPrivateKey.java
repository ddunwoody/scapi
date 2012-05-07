package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.PrivateKey;


/**
 * Interface for Rabin private key.
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public interface RabinPrivateKey extends RabinKey, PrivateKey{

	/**
	 * Returns prime1 (p), such that p*q=n
	 * @return BigInteger - prime1 (p)
	 */
	public BigInteger getPrime1();
	
	/**
	 * Returns prime2 (q), such that p*q=n
	 * @return BigInteger - prime2 (q)
	 */
	public BigInteger getPrime2();
	
	/**
	 * Returns the inverse of prime1 mod prime2
	 * @return BigInteger - inversePModQ (u)
	 */
	public BigInteger getInversePModQ();
}
