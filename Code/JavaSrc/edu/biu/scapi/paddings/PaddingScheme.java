package edu.biu.scapi.paddings;


/**
 * General interface for padding scheme. Every padding scheme, for example PKCS7, should implement this interface.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface PaddingScheme{
	/**
	 * Pads the given byte array with padSize bytes according to this padding scheme.
	 * @param padInput array to pad
	 * @param padSize number of bytes to add to padInput array
	 * @return the padded array
	 */
	public byte[] pad(byte[] padInput, int padSize);
	
	/**
	 * Removes the padding from the given byte array according to this padding scheme.
	 * @param paddedInput array to remove the padding from
	 * @return the array without the padding
	 */
	public byte[] removePad(byte[] paddedInput);
}
