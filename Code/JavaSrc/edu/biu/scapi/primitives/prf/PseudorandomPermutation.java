package edu.biu.scapi.primitives.prf;

import javax.crypto.IllegalBlockSizeException;

/** 
 * General interface for pseudorandom permutations which is sub-interface of pseudorandon function. Every prp class should implement this interface. <p>
 * Pseudorandom permutations are bijective pseudorandom functions that are efficiently invertible. 
 * As such, they are of the pseudorandom function type and their input length always equals their output length. 
 * In addition (and unlike general pseudorandom functions), they are efficiently invertible.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface PseudorandomPermutation extends PseudorandomFunction {
	/** 
	 * Inverts the permutation using the given key. <p>
	 * This function is a part of the PseudorandomPermutation interface since any PseudorandomPermutation must be efficiently invertible (given the key). 
	 * For block ciphers, for example, the length is known in advance and so there is no need to specify the length.
	 * @param inBytes input bytes to invert.
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to put the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException;
	
	/** 
	 * Inverts the permutation using the given key. <p>
	 * Since PseudorandomPermutation can also have varying input and output length (although the input and the output should be the same length), 
	 * the common parameter <code>len<code> of the input and the output is needed.
	 * @param inBytes input bytes to invert.
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to put the result from
	 * @param len the length of the input and the output
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff, int len) throws IllegalBlockSizeException;
}