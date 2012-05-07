package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;


/** 
 * General interface for trapdoor permutation elements. Every concrete element class should implement this interface.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
  */
public interface TPElement {

	/**
	 * Returns the trapdoor element value as BigInteger.
	 * @return the value of the element
	 */
	public BigInteger getElement();
	
	
}