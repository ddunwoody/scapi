package edu.biu.scapi.primitives.prf;

/** 
 * General interface for pseudorandom permutation with varying input and output lengths. 
 * A pseudorandom permutation with varying input/output lengths does not have predefined input /output lengths. 
 * The input and output length (that must be equal) may be different for each function call. 
 * The length of the input and output is determined upon user request. 
 * The interface PrpVaryingIOLength, groups and provides type safety for every PRP with varying input/output length. 
 * 
  * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface PrpVaryingIOLength extends PseudorandomPermutation,
		PrfVaryingIOLength {
}