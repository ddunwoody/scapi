package edu.biu.scapi.primitives.prf;

/** 
 * General interface for pseudorandom function with varying input length. 
 * A pseudorandom function with varying input length does not have predefined input length. 
 * The input length may be different for each function call, and is determined upon user request. 
 * The interface PrfVaryingInputLength, groups and provides type safety for every PRF with varying input length. 
 * 
  * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface PrfVaryingInputLength extends PseudorandomFunction {
}