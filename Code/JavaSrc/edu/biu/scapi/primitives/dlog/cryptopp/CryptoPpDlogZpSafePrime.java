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


package edu.biu.scapi.primitives.dlog.cryptopp;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import edu.biu.scapi.primitives.dlog.DlogGroupAbs;
import edu.biu.scapi.primitives.dlog.DlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.dlog.ZpElement;
import edu.biu.scapi.primitives.dlog.ZpElementSendableData;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.math.MathAlgorithms;

/**
 * This class implements a Dlog group over Zp* utilizing Crypto++'s implementation.<p>
 * It uses JNI technology to call Crypto++'s native code.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class CryptoPpDlogZpSafePrime extends DlogGroupAbs implements DlogZpSafePrime, DDH{

	private long pointerToGroup = 0; // pointer to the native group object

	/* native functions for the Dlog functionality */
	private native long createDlogZp(byte[] p, byte[] q, byte[] g);
	private native long createRandomDlogZp(int numBits);
	private native long getGenerator(long group);
	private native byte[] getP(long group);
	private native byte[] getQ(long group);
	private native long inverseElement(long group, long element);
	private native long exponentiateElement(long group, long element, byte[] exponent);
	private native long multiplyElements(long group, long element1, long element2);
	private native void deleteDlogZp(long group);
	private native boolean validateZpGroup(long group);
	private native boolean validateZpGenerator(long group);
	private native boolean validateZpElement(long group, long element);

	
	
	/**
	 * Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	 * @param groupParams - contains the group parameters
	 */
	public CryptoPpDlogZpSafePrime(ZpGroupParams groupParams) {

		this(groupParams, new SecureRandom());
	}
	
	/**
	 * Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	 * @param groupParams - contains the group parameters
	 */
	public CryptoPpDlogZpSafePrime(ZpGroupParams groupParams, SecureRandom random) {

		this.random = random;
		BigInteger p = groupParams.getP();
		BigInteger q = groupParams.getQ();
		BigInteger g = groupParams.getXg();

		// if p is not 2q+1 throw exception
		if (!q.multiply(new BigInteger("2")).add(BigInteger.ONE).equals(p)) {
			throw new IllegalArgumentException("p must be equal to 2q+1");
		}
		// if p is not a prime throw exception
		if (!p.isProbablePrime(40)) {
			throw new IllegalArgumentException("p must be a prime");
		}
		// if q is not a prime throw exception
		if (!q.isProbablePrime(40)) {
			throw new IllegalArgumentException("q must be a prime");
		}
		// set the inner parameters
		this.groupParams = groupParams;

		//Create CryptoPP Dlog group with p, ,q , g.
		//The validity of g will be checked after the creation of the group because the check need the pointer to the group
		pointerToGroup = createDlogZp(p.toByteArray(), q.toByteArray(), g.toByteArray());
		
		//If the generator is not valid, delete the allocated memory and throw exception 
		if (!validateZpGenerator(pointerToGroup)) {
			deleteDlogZp(pointerToGroup);
			throw new IllegalArgumentException("generator value is not valid");
		}
		//Create the GroupElement - generator with the pointer that return from the native function
		generator = new ZpSafePrimeElementCryptoPp(g, p, false);
		
		//Now that we have p, we can calculate k which is the maximum length of a string to be converted to a Group Element of this group.
		k = calcK(p);
	}

	/**
	 * Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	 * @param q the order of the group
	 * @param g the generator of the group
	 * @param p the prime of the group
	 */
	public CryptoPpDlogZpSafePrime(String q, String g, String p) {
		//creates ZpGroupParams from the given arguments and call the appropriate constructor
		this(new ZpGroupParams(new BigInteger(q), new BigInteger(g), new BigInteger(p)));
	}
	
	/**
	 * Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	 * @param q the order of the group
	 * @param g the generator of the group
	 * @param p the prime of the group
	 * @throws NoSuchAlgorithmException 
	 */
	public CryptoPpDlogZpSafePrime(String q, String g, String p, String randNumGenAlg) throws NoSuchAlgorithmException {
		//creates ZpGroupParams from the given arguments and call the appropriate constructor
		this(new ZpGroupParams(new BigInteger(q), new BigInteger(g), new BigInteger(p)), SecureRandom.getInstance(randNumGenAlg));
	}

	/**
	 * Default constructor. Initializes this object with 1024 bit size.
	 */
	public CryptoPpDlogZpSafePrime() {
		this(1024);
	}

	/**
	 * Initializes the CryptoPP implementation of Dlog over Zp* with random elements
	 * @param numBits - number of the prime p bits to generate
	 */
	public CryptoPpDlogZpSafePrime(int numBits) {

		this(numBits, new SecureRandom());
	}
	
	/**
	 * Initializes the CryptoPP implementation of Dlog over Zp* with random elements
	 * @param numBits - number of the prime p bits to generate
	 */
	public CryptoPpDlogZpSafePrime(int numBits, SecureRandom random){
		
		this.random = random;
		
		// create random Zp dlog group
		pointerToGroup = createRandomDlogZp(numBits);

		// get the generator value
		long pGenerator = getGenerator(pointerToGroup);
		//create the GroupElement - generator with the pointer that returned from the native function
		generator = new ZpSafePrimeElementCryptoPp(pGenerator);

		BigInteger p = new BigInteger(getP(pointerToGroup));
		BigInteger q = new BigInteger(getQ(pointerToGroup));
		BigInteger xG = ((ZpElement) generator).getElementValue();

		groupParams = new ZpGroupParams(q, xG, p);

		//Now that we have p, we can calculate k which is the maximum length in bytes of a string to be converted to a Group Element of this group. 
		k = calcK(p);
	}

	public CryptoPpDlogZpSafePrime(String numBits) {
		//creates an int from the given string and calls the appropriate constructor
		this(new Integer(numBits));
	}
	
	public CryptoPpDlogZpSafePrime(String numBits, String randNumGenAlg) throws NoSuchAlgorithmException {
		//creates an int from the given string and calls the appropriate constructor
		this(new Integer(numBits), SecureRandom.getInstance(randNumGenAlg));
	}
	
	private int calcK(BigInteger p){
		int bitsInp = p.bitLength();
		//any string of length k has a numeric value that is less than (p-1)/2 - 1
		int k = (bitsInp - 3)/8; 
		//The actual k that we allow is one byte less. This will give us an extra byte to pad the binary string passed to encode to a group element with a 01 byte
		//and at decoding we will remove that extra byte. This way, even if the original string translates to a negative BigInteger the encode and decode functions
		//always work with positive numbers. The encoding will be responsible for padding and the decoding will be responsible for removing the pad.
		k--; 
		//For technical reasons of how we chose to do the padding for encoding and decoding (the least significant byte of the encoded string contains the size of the 
		//the original binary string sent for encoding, which is used to remove the padding when decoding) k has to be <= 255 bytes so that the size can be encoded in the padding.
		if( k > 255){
			k = 255;
		}
		return k;
	}
	
	/**
	 * @return the type of the group - Zp*
	 */
	public String getGroupType() {
		return "Zp*";
	}

	/**
	 * 
	 * @return the identity of this Zp group - 1
	 */
	public GroupElement getIdentity() {
		return new ZpSafePrimeElementCryptoPp(BigInteger.ONE, ((ZpGroupParams) groupParams).getP(), false);
	}
	
	/**
	 * Creates a random member of this Dlog group
	 * 
	 * @return the random element
	 */
	public GroupElement createRandomElement() {
		//This function overrides the basic implementation of DlogGroupAbs. For the case of Zp Safe Prime this is a more efficient implementation.
		//It calls the package private constructor of ZpSafePrimeElementCryptoPp, which randomly creates an element in Zp.
		return new ZpSafePrimeElementCryptoPp(((ZpGroupParams) groupParams).getP(), random);

	}

	/**
	 * Checks if the given element is member of this Dlog group
	 * @param element 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) {

		// check if element is ZpElementCryptoPp
		if (!(element instanceof ZpSafePrimeElementCryptoPp)) {
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		
		return validateZpElement(pointerToGroup, ((ZpSafePrimeElementCryptoPp) element).getPointerToElement());

	}

	/**
	 * Checks if the given generator is indeed the generator of the group
	 * @return true, is the generator is valid, false otherwise.
	 */
	public boolean isGenerator() {

		return validateZpGenerator(pointerToGroup);
	}

	/**
	 * Checks if the parameters of the group are correct.
	 * @return true if valid, false otherwise.
	 */
	public boolean validateGroup() {

		return validateZpGroup(pointerToGroup);
	}

	/**
	 * Calculates the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		
		if (groupElement instanceof ZpSafePrimeElementCryptoPp){
			//call to native inverse function
			long invertVal = inverseElement(pointerToGroup, ((ZpSafePrimeElementCryptoPp) groupElement).getPointerToElement());
			
			//build a ZpElementCryptoPp element from the result value
			ZpSafePrimeElementCryptoPp inverseElement = new ZpSafePrimeElementCryptoPp(invertVal);
			
			return inverseElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	/**
	 * Raises the base GroupElement to the exponent. The result is another GroupElement.
	 * @param exponent
	 * @param base
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(GroupElement base, BigInteger exponent) throws IllegalArgumentException{
		
		if (base instanceof ZpSafePrimeElementCryptoPp){
			//call to native exponentiate function
			long exponentiateVal = exponentiateElement(pointerToGroup, ((ZpSafePrimeElementCryptoPp) base).getPointerToElement(), exponent.toByteArray());
			
			//build a ZpElementCryptoPp element from the result value
			ZpSafePrimeElementCryptoPp exponentiateElement = new ZpSafePrimeElementCryptoPp(exponentiateVal);
			
			return exponentiateElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	/**
	 * Multiplies two GroupElements
	 * 
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1,
			GroupElement groupElement2) throws IllegalArgumentException {

		if ((groupElement1 instanceof ZpSafePrimeElementCryptoPp) && (groupElement2 instanceof ZpSafePrimeElementCryptoPp)){
			// call to native multiply function
			long mulVal = multiplyElements(pointerToGroup, ((ZpSafePrimeElementCryptoPp) groupElement1).getPointerToElement(), 
										  ((ZpSafePrimeElementCryptoPp) groupElement2).getPointerToElement());

			// build a ZpElementCryptoPp element from the result value
			ZpSafePrimeElementCryptoPp mulElement = new ZpSafePrimeElementCryptoPp(mulVal);
			
			return mulElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	/**
	 * Computes the product of several exponentiations with distinct bases 
	 * and distinct exponents. 
	 * Instead of computing each part separately, an optimization is used to 
	 * compute it simultaneously. 
	 * @param groupElements
	 * @param exponentiations
	 * @return the exponentiation result
	 */
	@Override
	public GroupElement simultaneousMultipleExponentiations
				(GroupElement[] groupElements, BigInteger[] exponentiations){
		
		for (int i=0; i < groupElements.length; i++){
			if (!(groupElements[i] instanceof ZpSafePrimeElementCryptoPp)){
				throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
			}
		}
		//currently, in cryptoPpDlogZpSafePrime the native algorithm is faster than the optimized one due to many calls to the JNI.
		//Thus, we operate the native algorithm. In the future we may change this.
		return computeNaive(groupElements, exponentiations);

	}

	/**
	 * @deprecated As of SCAPI-V2_0_0 use generateElment(boolean bCheckMembership, BigInteger...values)
	 */
	@Deprecated public ZpElement generateElement(Boolean bCheckMembership, BigInteger x) {

		return new ZpSafePrimeElementCryptoPp(x, ((ZpGroupParams) groupParams).getP(), bCheckMembership);
	}
	
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.primitives.dlog.DlogGroup#generateElement(boolean, java.math.BigInteger[])
	 */
	@Override
	public GroupElement generateElement(boolean bCheckMembership, BigInteger... values) throws IllegalArgumentException {
		if(values.length != 1){
			throw new IllegalArgumentException("To generate an ZpElement you should pass the x value of the point");
		}
				
		return new ZpSafePrimeElementCryptoPp(values[0], ((ZpGroupParams) groupParams).getP(), bCheckMembership);
		
	}
	
	/**
	 * @see edu.biu.scapi.primitives.dlog.DlogGroup#generateElement(boolean, edu.biu.scapi.primitives.dlog.GroupElementSendableData)
	 * @deprecated The name of this function was changed.As of SCAPI-V1-0-2-2 use {@link reconstructElement(boolean bCheckMembership, GroupElementSendableData data)} instead.
	 */
	@Override
	@Deprecated public GroupElement generateElement(boolean bCheckMembership, GroupElementSendableData data) {
		if (!(data instanceof ZpElementSendableData))
			throw new IllegalArgumentException("data type doesn't match the group type");
		return generateElement(bCheckMembership, ((ZpElementSendableData)data).getX());
	}

	/**
	 * @see edu.biu.scapi.primitives.dlog.DlogGroup#reconstructElement(boolean, edu.biu.scapi.primitives.dlog.GroupElementSendableData)
	 * @throws IllegalArgumentException if bCheckMembership is true and the data does not correspond to an illegal value of this group
	 */
	@Override
	public GroupElement reconstructElement(boolean bCheckMembership, GroupElementSendableData data) {
		if (!(data instanceof ZpElementSendableData))
			throw new IllegalArgumentException("data type doesn't match the group type");
		return generateElement(bCheckMembership, ((ZpElementSendableData)data).getX());
	}
	
	/**
	 * deletes the related Dlog group object
	 */
	protected void finalize() throws Throwable {

		// delete from the dll the dynamic allocation of the Integer.
		deleteDlogZp(pointerToGroup);

		super.finalize();
	}


	/**
	 * This function takes any string of length up to k bytes and encodes it to a Group Element.<p>
	 * k is calculated upon construction of this group and it depends on the length in bits of p.<p>
	 * The encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.<p>
	 * Therefore, any string of length in bytes up to k can be encoded to a group element but not<p>
	 * every group element can be decoded to a binary string in the group of binary strings of length up to 2^k.<p>
	 * Thus, the right way to use this functionality is first to encode a byte array and the to decode it, and not the opposite.
	 * @throws IndexOutOfBoundsException if the length of the binary array to encode is longer than k
	 */
	public GroupElement encodeByteArrayToGroupElement(byte[] binaryString) {
		//Any string of length up to k has numeric value that is less than (p-1)/2 - 1.
		//If longer than k then throw exception.
		if (binaryString.length > k){
			throw new IndexOutOfBoundsException("The binary array to encode is too long.");
		}
	
		//Pad the binaryString with a x01 byte in the most significant byte to ensure that the 
		//encoding and decoding always work with positive numbers.
		byte[] newString = new byte[binaryString.length + 1];
		newString[0] = 1;
		System.arraycopy(binaryString, 0, newString, 1, binaryString.length);
	
		//Denote the string of length k by s.
		//Set the group element to be y=(s+1)^2 (this ensures that the result is not 0 and is a square)
		BigInteger s = new BigInteger(newString);
		BigInteger y = (s.add(BigInteger.ONE)).pow(2).mod(((ZpGroupParams) groupParams).getP());
		//There is no need to check membership since the "element" was generated so that it is always an element.
		ZpSafePrimeElementCryptoPp element = new ZpSafePrimeElementCryptoPp(y, ((ZpGroupParams) groupParams).getP(), false);
		return element;
	}
	
	/**
	 * This function decodes a group element to a byte array.<p> 
	 * This function is guaranteed to work properly ONLY if the group element was obtained as a result
	 * of encoding a binary string of length in bytes up to k. This is because the encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.<p>
	 * Therefore, any string of length in bytes up to k can be encoded to a group element but not<p>
	 * any group element can be decoded to a binary sting in the group of binary strings of length up to 2^k.
	 * @param groupElement the GroupElement to decode
	 * @return a byte[] decoding of the group element
	 */
	public byte[] decodeGroupElementToByteArray(GroupElement groupElement) {
		if (!(groupElement instanceof ZpSafePrimeElementCryptoPp)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		
		//Given a group element y, find the two inverses z,-z. Take z to be the value between 1 and (p-1)/2. Return s=z-1
		BigInteger y = ((ZpElement) groupElement).getElementValue();
		BigInteger p = ((ZpGroupParams) groupParams).getP();
		MathAlgorithms.SquareRootResults roots = MathAlgorithms.sqrtModP_3_4(y, p);
	
		BigInteger goodRoot;
		BigInteger halfP = (p.subtract(BigInteger.ONE)).divide(BigInteger.valueOf(2));
		if(roots.getRoot1().compareTo(BigInteger.ONE)>= 0 && roots.getRoot1().compareTo(halfP) < 0)
			goodRoot = roots.getRoot1();
		else 
			goodRoot = roots.getRoot2();
		
		goodRoot = goodRoot.subtract(BigInteger.ONE);
	
		//Remove the padding byte at the most significant position (that was added while encoding)
		byte[] rootByteArray = goodRoot.toByteArray();
		byte[] oneByteLess = new byte[rootByteArray.length -1];
		System.arraycopy(rootByteArray, 1, oneByteLess, 0,oneByteLess.length );
		return oneByteLess;
	}

	
	/**
	 * This function maps a group element of this dlog group to a byte array.<p>
	 * This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array. 
	 * @return a byte array representation of the given group element
	 */
	public byte[] mapAnyGroupElementToByteArray(GroupElement groupElement){
		if (!(groupElement instanceof ZpSafePrimeElementCryptoPp)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		return ((ZpElement) groupElement).getElementValue().toByteArray();		
	}

	// upload CryptoPP library
	static {
		System.loadLibrary("CryptoPPJavaInterface");
	}

	
}
