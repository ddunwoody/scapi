package edu.biu.scapi.primitives.prf;

/** 
 * General interface for pseudorandom function with varying input and output lengths. 
 * A pseudorandom function with varying input/output lengths does not have predefined input and output lengths. 
 * The input and output length may be different for each compute function call. 
 * The length of the input as well as the output is determined upon user request.
 * The interface PrfVaryingIOLength, groups and provides type safety for every PRF with varying input and output length
 * 
  * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface PrfVaryingIOLength extends PseudorandomFunction {
}