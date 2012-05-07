package edu.biu.scapi.primitives.prf;

/** 
 * General interface for pseudorandom permutation with fixed input and output lengths.
 * A pseudorandom permutation with fixed lengths predefined input and output lengths, and there is no need to specify it for each function call. 
 * Block ciphers, for example, have known lengths and so they implement this interface.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface PrpFixed extends PseudorandomPermutation, PrfFixed {
}