/**
 * 
 */
package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class RSAModulus{
	public BigInteger p;
	public BigInteger q;
	public BigInteger n;
	public RSAModulus(BigInteger p , BigInteger q, BigInteger n){
		this.p = p;
		this.q = q;
		this.n = n;
	}
}