/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


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
* The two most common classes are the group Zp* for a large p, and some Elliptic curve groups.<p>
*  
* Another issue pertaining elliptic curves is the need to find a suitable mapping that will convert an arbitrary message (that is some binary string) to an element of the group and vice-versa.<p> 
* Only a subset of the messages can be effectively mapped to a group element in such a way that there is a one-to-one injection that converts the string to a group element and vice-versa.<p> 
* On the other hand, any group element can be mapped to some string.<p> 
* In this case, the operation is not invertible. This functionality is implemented by the functions:<p>
*  - {@code encodeByteArrayToGroupElement(byte[] binaryString) : GroupElement}<p>
*  - {@code decodeGroupElementToByteArray(GroupElement element) : byte[]}<p>
*  - {@code mapAnyGroupElementToByteArray(GroupElement element) : byte[]}<p>
*  
*  The first two work as a pair and decodeGroupElementToByteArray is the inverse of encodeByteArrayToGroupElement, whereas the last one works alone and does not have an inverse. 

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
	 * @return <code>true</code> if the given element is a member of this group;<p> 
	 * 		   <code>false</code> otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException;
	
	/**
	 * Checks if the order is a prime number
	 * @return <code>true<code> if the order is a prime number; <p>
	 * 		   <code>false</code> otherwise.
	 * 
	 */
	public boolean isPrimeOrder();
	
	/**
	 * Checks if the order of this group is greater than 2^numBits
	 * @param numBits
	 * @return <code>true</code> if the order is greater than 2^numBits;<p>
	 * 		   <code>false</code> otherwise.
	 */
	public boolean isOrderGreaterThan(int numBits);
	
	/**
	 * Checks if the element set as the generator is indeed the generator of this group.
	 * @return <code>true</code> if the generator is valid;<p>
	 *         <code>false</code> otherwise.
	 */
	public boolean isGenerator();
	
	/**
	 * Checks parameters of this group to see if they conform to the type this group is supposed to be. 
	 * @return <code>true</code> if valid;<p>
	 *  	   <code>false</code> otherwise.
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
	 * @throws IllegalArgumentException
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
	 * This function allows the generation of a group element by a protocol that holds a Dlog Group but does not know if it is a Zp Dlog Group or an Elliptic Curve Dlog Group.
	 * It receives the possible values of a group element and whether to check membership of the group element to the group or not.
	 * It may be not necessary to check membership if the source of values is a trusted source (it can be the group itself after some calculation). On the other hand,
	 * to work with a generated group element that is not really an element in the group is wrong. It is up to the caller of the function to decide if to check membership or not.
	 * If bCheckMembership is false always generate the element. Else, generate it only if the values are correct. 
	 * @param bCheckMembership
	 * @param values
	 * @return the generated GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement generateElement(boolean bCheckMembership, BigInteger...values) throws IllegalArgumentException;
	
	/**
	 * @deprecated The name of this function was changed.As of SCAPI-V1-0-2-2 use {@link reconstructElement(boolean bCheckMembership, GroupElementSendableData data)} instead.
	 * @param bCheckMembership
	 * @param data
	 * @return
	 */
	@Deprecated public GroupElement generateElement(boolean bCheckMembership, GroupElementSendableData data);
	
	/**
	 * Reconstructs a GroupElement given the GroupElementSendableData data, which might have been received through a Channel open between the party holding this DlogGroup and 
	 * some other party. 
	 * @param bCheckMembership whether to check that the data provided can actually reconstruct an element of this DlogGroup. Since this action is expensive it should be used only if necessary. 
	 * @param data the GroupElementSendableData from which we wish to "reconstruct" an element of this DlogGroup 
	 * @return the reconstructed GroupElement
	 */
	public GroupElement reconstructElement(boolean bCheckMembership, GroupElementSendableData data);
	
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
	 * @param base
	 * @param exponent
	 * @return the exponentiation result
	 */
	public GroupElement exponentiateWithPreComputedValues(GroupElement base, BigInteger exponent);
	
	/**
	 * This function cleans up any resources used by exponentiateWithPreComputedValues for the requested base.
	 * It is recommended to call it whenever an application does not need to continue calculating exponentiations for this specific base.   
	 * 
	 * @param base
	 */
	public void endExponentiateWithPreComputedValues(GroupElement base);
	
	/**
	 * This function takes any string of length up to k bytes and encodes it to a Group Element. 
	 * k can be obtained by calling getMaxLengthOfByteArrayForEncoding() and it is calculated upon construction of this group; it depends on the length in bits of p.<p>
	 * The encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto. 
	 * Therefore, any string of length in bytes up to k can be encoded to a group element but not every group element can be decoded to a binary string in the group of binary strings of length up to 2^k.<p>
	 * Thus, the right way to use this functionality is first to encode a byte array and then to decode it, and not the opposite.
	 * 
	 * @param binaryString the byte array to encode
	 * @return the encoded group Element <B> or null </B>if element could not be encoded
	 */
	public GroupElement encodeByteArrayToGroupElement(byte[] binaryString);
	
	/**
	 * This function decodes a group element to a byte array. This function is guaranteed to work properly ONLY if the group element was obtained as a result of 
	 * encoding a binary string of length in bytes up to k.<p>
	 * This is because the encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto. 
	 * Therefore, any string of length in bytes up to k can be encoded to a group element but not any group element can be decoded 
	 * to a binary sting in the group of binary strings of length up to 2^k.
	 * 
	 * @param groupElement the element to decode
	 * @return the decoded byte array
	 */
	public byte[] decodeGroupElementToByteArray(GroupElement groupElement);
	
	
	/**
	 * This function returns the value <I>k</I> which is the maximum length of a string to be encoded to a Group Element of this group.<p>
	 * Any string of length <I>k</I> has a numeric value that is less than (p-1)/2 – 1.
	 * <I>k</I> is the maximum length a binary string is allowed to be in order to encode the said binary string to a group element and vice-versa.<p>
	 * If a string exceeds the <I>k</I> length it cannot be encoded.
	 * @return k the maximum length of a string to be encoded to a Group Element of this group. k can be zero if there is no maximum.
	 */
	public int getMaxLengthOfByteArrayForEncoding();
	
	/**
	 * This function maps a group element of this dlog group to a byte array.<p>
	 * This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array. 
	 * @return a byte array representation of the given group element
	 */
	public byte[] mapAnyGroupElementToByteArray(GroupElement groupElement);
}
