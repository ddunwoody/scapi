package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
* This is the general interface for the discrete logarithm group. Every class in the DlogGroup family implements this interface.
* <p>
* The discrete logarithm problem is as follows: given a generator g of a finite 
* group G and a random element h in G, find the (unique) integer x such that 
* g^x = h.<p> 
* In cryptography, we are interested in groups for which the discrete logarithm problem (Dlog for short) is assumed to be hard.<p> 
* The two most common classes are the group Zp* for a large p, and some Elliptic curve groups.
* 
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)

 *
 */
public interface DlogGroup {

	/**
	 * Each concrete class implementing this interface returns a string with a meaningful name for this type of Dlog group. 
	 * For example: "elliptic curve over F2m" or "Zp*"
	 * @return the name of the group type
	 */
	public String getGroupType();
	
	/**
	 * The generator g of the group is an element of the group such that, when written multiplicatively, every element of the group is a power of g.
	 * @return the generator of this Dlog group
	 */
	public GroupElement getGenerator();
	
	/**
	 * GroupParams is a structure that holds the actual data that makes this group a specific Dlog group.<p> 
	 * For example, for a Dlog group over Zp* what defines the group is p. 
	 * 
	 * @return the GroupParams of that Dlog group
	 */
	public GroupParams getGroupParams();
	
	/**
	 * 
	 * @return the order of this Dlog group
	 */
	public BigInteger getOrder();
	
	/**
	 * 
	 * @return the identity of this Dlog group
	 */
	public GroupElement getIdentity();
	
	/**
	 * Checks if the given element is a member of this Dlog group
	 * @param element possible group element for which to check that it is a member of this group
	 * @return <code>true<code> if the given element is a member of this group; <code>false<code> otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException;
	
	/**
	 * Checks if the order is a prime number
	 * @return <code>true<code> if the order is a prime number; <code>false<code> otherwise.
	 * 
	 */
	public boolean isPrimeOrder();
	
	/**
	 * Checks if the order of this group is greater than 2^numBits
	 * @param numBits
	 * @return <code>true<code> if the order is greater than 2^numBits; <code>false<code> otherwise.
	 */
	public boolean isOrderGreaterThan(int numBits);
	
	/**
	 * Checks if the element set as the generator is indeed the generator of this group.
	 * @return <code>true<code> if the generator is valid; <code>false<code> otherwise.
	 */
	public boolean isGenerator();
	
	/**
	 * Checks parameters of this group to see if they conform to the type this group is supposed to be. 
	 * @return <code>true<code> if valid; <code>false<code> otherwise.
	 */
	public boolean validateGroup();
	
	/**
	 * Calculates the inverse of the given GroupElement.
	 * @param groupElement to invert
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 **/
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException;
	
	/**
	 * Raises the base GroupElement to the exponent. The result is another GroupElement.
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(GroupElement base, BigInteger exponent) throws IllegalArgumentException;
	
	/**
	 * Multiplies two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, GroupElement groupElement2) throws IllegalArgumentException;
	
	/**
	 * Creates a random member of this Dlog group
	 * @return the random element 
	 */
	public GroupElement createRandomElement();
	
	/**
	 * Creates a random generator of this Dlog group
	 * @return the random generator 
	 */
	public GroupElement createRandomGenerator();
	
	
	/**
	 * Computes the product of several exponentiations with distinct bases 
	 * and distinct exponents. 
	 * Instead of computing each part separately, an optimization is used to 
	 * compute it simultaneously. 
	 * @param groupElements
	 * @param exponentiations
	 * @return the exponentiation result
	 */
	public GroupElement simultaneousMultipleExponentiations(GroupElement[] groupElements, BigInteger[] exponentiations);
	
	/**
	 * Computes the product of several exponentiations of the same base
	 * and distinct exponents. 
	 * An optimization is used to compute it more quickly by keeping in memory 
	 * the result of h1, h2, h4,h8,... and using it in the calculation.<p>
	 * Note that if we want a one-time exponentiation of h it is preferable to use the basic exponentiation function 
	 * since there is no point to keep anything in memory if we have no intention to use it. 
	 * @param groupElement
	 * @param exponent
	 * @return the exponentiation result
	 */
	public GroupElement exponentiateWithPreComputedValues(GroupElement groupElement, BigInteger exponent);
	
	/**
	 * Converts a byte array to a GroupElement.
	 * @param binaryString the byte array to convert
	 * @return the created group Element or null if element could not be created
	 */
	public GroupElement encodeByteArrayToGroupElement(byte[] binaryString);
	
	/**
	 * Convert a GroupElement to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] decodeGroupElementToByteArray(GroupElement groupElement);
	
	
	/**
	 * This function returns the value k which is the maximum length of a string to be converted to a Group Element of this group.<p>
	 * If a string exceeds the k length it cannot be converted
	 * @return k the maximum length of a string to be converted to a Group Element of this group. k can be zero if there is no maximum.
	 */
	public int getMaxLengthOfByteArrayForEncoding();
	
	/**
	 * This function maps a group element of this dlog group to a byte array.<p>
	 * This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array. 
	 * @return a byte array representation of the given group element
	 */
	public byte[] mapAnyGroupElementToByteArray(GroupElement groupElement);
}
