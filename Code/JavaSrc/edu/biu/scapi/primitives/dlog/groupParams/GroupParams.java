package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

/*
 * The GroupParams family holds the necessary parameters for each possible concrete Dlog group. <p>
 * Each DlogGroup has different parameters that constitute this group. GroupParams classes hold those parameters.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class GroupParams implements AlgorithmParameterSpec {

	protected BigInteger q; //the group order

	/*
	 * Returns the group order, which is the number of elements in the group
	 * @return the order of the group
	 */
	public BigInteger getQ() { 
		return q;
	}
}
