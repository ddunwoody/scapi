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


package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;

/**
 * Concrete class of trapdoor permutation for RSA.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public final class ScRSAPermutation extends TrapdoorPermutationAbs implements RSAPermutation {

	private SecureRandom random;

	public ScRSAPermutation(){
		this(new SecureRandom());
	}

	public ScRSAPermutation(SecureRandom random){
		this.random = random;
	}

	public ScRSAPermutation(String randNumGenAlg) throws NoSuchAlgorithmException{
		this(SecureRandom.getInstance(randNumGenAlg));
	}

	
	/** 
	 * Initializes this RSA permutation with keys
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException if the keys are not RSA keys
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {

		if (!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}

		modulus = ((RSAPublicKey)publicKey).getModulus();

		//calls the father init that sets the keys
		super.setKey(publicKey, privateKey);

	}

	/** 
	 * Initializes this RSA permutation with public key.
	 * After this initialization, this object can do compute but not invert.
	 * This initialization is for user that wants to encrypt a message using the public key but deosn't want to decrypt a message.
	 * @param publicKey - public key
	 * @throws InvalidKeyException if the key is not a RSA key
	 */
	public void setKey(PublicKey publicKey) throws InvalidKeyException {

		if (!(publicKey instanceof RSAPublicKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}

		modulus = ((RSAPublicKey)publicKey).getModulus();

		//calls the father init that sets the key
		super.setKey(publicKey);

	}

	/** 
	 * @return the algorithm name - "RSA"
	 */
	public String getAlgorithmName() {
		return "RSA";
	}

	/** 
	 * Generate RSA public and private keys.
	 * @param params RSAKeyGenParameterSpec
	 * @throws InvalidParameterSpecException if params are not RSA parameter spec
	 */
	public KeyPair generateKey(AlgorithmParameterSpec params) throws InvalidParameterSpecException {
		KeyPair pair = null;
		if(!(params instanceof RSAKeyGenParameterSpec)) {
			throw new InvalidParameterSpecException("AlgorithmParameterSpec type doesn't match the trapdoor permutation type");
		}

		try {
			/*generates public and private keys */
			KeyPairGenerator kpr;
			kpr = KeyPairGenerator.getInstance("RSA");
			kpr.initialize(((RSAKeyGenParameterSpec) params).getKeysize(), random);
			pair = kpr.generateKeyPair();

		} catch (NoSuchAlgorithmException e) {
			//shouldn't occur since RSA is a  valid algorithm
			Logging.getLogger().log(Level.WARNING, e.toString());
		} 

		return pair;
	}

	/**
	 * This function is not supported in this implementation. Throws exception.
	 * @throws UnsupportedOperationException 
	 */
	public KeyPair generateKey(){
		throw new UnsupportedOperationException("To generate keys for this RSA object use the generateKey(AlgorithmParameterSpec params) function");
	}

	/** 
	 * Computes the  RSA permutation on the given TPElement 
	 * @param tpEl - the input for the computation
	 * @return - the result TPElement
	 * @throws IllegalArgumentException if the given element is not a RSA element
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException{

		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}

		if (!(tpEl instanceof RSAElement)) {
			throw new IllegalArgumentException("trapdoor element doesn't match the trapdoor permutation");
		}

		// gets the value of the element 
		BigInteger element = ((RSAElement)tpEl).getElement();
		//compute - calculates (element^e)modN
		BigInteger result = element.modPow(
				((RSAPublicKey)pubKey).getPublicExponent(), ((RSAPublicKey)pubKey).getModulus());
		// builds the return element
		RSAElement returnEl = new RSAElement(modulus, result, false);	//create an RSAElement without checking since "result" is the result of the computation and it should be valid.		
		//returns the result of the computation
		return returnEl;
	}

	/** 
	 * Inverts the RSA permutation on the given TPElement.
	 * @param tpEl - the input to invert
	 * @return - the result 
	 * @throws IllegalArgumentException if the given element is not a RSA element
	 * @throws KeyException 
	 */
	public TPElement invert(TPElement tpEl)  throws IllegalArgumentException, KeyException{
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}

		//If the key set was only the public key and not the private key - can't do the invert, throw exception.
		if (privKey == null && pubKey!=null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}

		if (!(tpEl instanceof RSAElement)) {
			throw new IllegalArgumentException("trapdoor element doesn't match the trapdoor permutation");
		}

		// gets the value of the element 
		BigInteger element = ((RSAElement)tpEl).getElement();
		//invert the permutation
		BigInteger result = doInvert(element);
		//builds the return element
		RSAElement returnEl = new RSAElement(modulus, result, false); //create an RSAElement without checking since "result" is the result of the computation and it should be valid.
		//returns the result
		return returnEl;
	}

	/**
	 * Inverts the permutation according to the RSA key.
	 * If the key is CRT key - invert using the Chinese Remainder Theorem.
	 * Else - invert using d, modN.
	 * @param input - The element to invert
	 * @return BigInteger - the result
	 */
	private BigInteger doInvert(BigInteger input)
	{
		if (privKey instanceof RSAPrivateCrtKey) //invert with CRT parameters
		{
			// we have the extra factors, use the Chinese Remainder Theorem 
			RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey)privKey;

			//gets the crt parameters
			BigInteger p = crtKey.getPrimeP();
			BigInteger q = crtKey.getPrimeQ();
			BigInteger dP = crtKey.getPrimeExponentP();
			BigInteger dQ = crtKey.getPrimeExponentQ();
			BigInteger qInv = crtKey.getCrtCoefficient();

			BigInteger mP, mQ, h, m;

			// mP = ((input mod p) ^ dP)) mod p
			mP = (input.remainder(p)).modPow(dP, p);

			// mQ = ((input mod q) ^ dQ)) mod q
			mQ = (input.remainder(q)).modPow(dQ, q);

			// h = qInv * (mP - mQ) mod p
			h = mP.subtract(mQ);
			h = h.multiply(qInv);
			h = h.mod(p);               // mod returns the positive residual

			// m = h * q + mQ
			m = h.multiply(q);
			m = m.add(mQ);

			return m;
		}
		else{//invert using d, modN
			return input.modPow(
					((RSAPrivateKey)privKey).getPrivateExponent(), ((RSAPrivateKey)pubKey).getModulus());
		}
	}


	/** 
	 * Checks if the given element is valid to RSA permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * There are three possible validity values: 
	 * VALID (it is an element)
	 * NOT_VALID (it is not an element)
	 * DON’T_KNOW (there is not enough information to check if it is an element or not)  
	 * @throws IllegalArgumentException if the given element is not a RSA element
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException{
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		if (!(tpEl instanceof RSAElement)){
			throw new IllegalArgumentException("trapdoor element doesn't match the trapdoor permutation");
		}

		TPElValidity validity = null;
		BigInteger value = ((RSAElement)tpEl).getElement();

		//if mod n is unknown - returns DONT_KNOW 
		if (modulus==null) {
			validity = TPElValidity.DONT_KNOW;

			//if the value is valid (between 1 to (mod n) - 1) returns VALID 
		} else if(((value.compareTo(BigInteger.ZERO))>0) && (value.compareTo(modulus)<0)) {

			validity = TPElValidity.VALID;
			//if the value is invalid returns NOT_VALID 
		} else {
			validity = TPElValidity.NOT_VALID;
		}		

		//returns the correct TPElValidity
		return validity;
	}

	/** 
	 * Creates a random RSAElement 
	 * @return TPElement - the created RSA element
	 */
	public TPElement generateRandomTPElement(){
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		return new RSAElement(modulus);
	}
	
	/** 
	 * Creates an RSA Element from a specific value x. It checks that the x value is valid for this trapdoor permutation.
	 * @return TPElement - If the x value is valid for this permutation return the created random element
	 * @throws  IllegalArgumentException if the given value x is invalid for this permutation
	 * @throws IllegalStateException if the keys aren't set
	 */
	public TPElement generateTPElement(BigInteger x) throws IllegalArgumentException {
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		return new RSAElement(modulus, x, true);
	}

	/** 
	 * Creates an RSA Element from a specific value x. It checks that the x value is valid for this trapdoor permutation.
	 * @return TPElement - If the x value is valid for this permutation return the created random element
	 * @throws  IllegalArgumentException if the given value x is invalid for this permutation
	 * @throws IllegalStateException if the keys aren't set
	 */
	public TPElement generateUncheckedTPElement(BigInteger x) throws IllegalArgumentException {
	
		return new RSAElement(modulus, x, false);
	}

	/**
	 * This function generates an RSA modulus N with "length" bits of length, such that N = p*q, and p and q
	 * @param length the length in bits of the RSA modulus
	 * @param certainty the certainty required regarding the primeness of p and q
	 * @param random a source of randomness
	 * @return an RSAModulus structure that holds N, p and q.
	 */
	public static RSAModulus generateRSAModulus(int length, int certainty, SecureRandom random){

		BigInteger p, q, n;
		int pbitlength = (length + 1) / 2;
		int qbitlength = length - pbitlength;
		int mindiffbits = length / 3;
	

		// generate p prime
		for (;;) {
			p = new BigInteger(pbitlength, 1, random); 
			if (p.isProbablePrime(certainty)) {
				break;
			}           
		}

		for(;;){
			for (;;) {
				q = new BigInteger(qbitlength, 1, random); 
				if(q.subtract(p).abs().bitLength() < mindiffbits){
					continue;
				}
				if (q.isProbablePrime(certainty)) {
					break;
				}           
			}

			// calculate the modulus
			n = p.multiply(q);

			if (n.bitLength() == length) 
			{
				break;
			} 

			//
			// if we get here our primes aren't big enough, make the largest
			// of the two p and try again
			//
			p = p.max(q);
		}

		return new RSAModulus(p,q, n);
	}

}
