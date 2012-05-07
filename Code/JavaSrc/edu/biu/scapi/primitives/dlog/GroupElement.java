package edu.biu.scapi.primitives.dlog;

/**
 * This is the main interface of the Group element hierarchy.<p> 
 * We can refer to a group element as a general term OR we can relate to the fact that an element of an elliptic curve
 * is a point and an element of a Zp group is a number between 0 and p-1.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface GroupElement {
	/**
	 * Release the memory allocated for this element.
	 * This function should be called when the element need to be deleted.
	 */
	public void release();
}
