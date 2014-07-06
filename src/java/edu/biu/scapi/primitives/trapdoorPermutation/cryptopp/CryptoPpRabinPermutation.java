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


package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.ScapiRuntimeException;
import edu.biu.scapi.primitives.trapdoorPermutation.RabinKeyGenParameterSpec;
import edu.biu.scapi.primitives.trapdoorPermutation.RabinPermutation;
import edu.biu.scapi.primitives.trapdoorPermutation.RabinPrivateKey;
import edu.biu.scapi.primitives.trapdoorPermutation.RabinPublicKey;
import edu.biu.scapi.primitives.trapdoorPermutation.ScRabinPrivateKey;
import edu.biu.scapi.primitives.trapdoorPermutation.ScRabinPublicKey;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElValidity;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutationAbs;

/** 
 * Concrete class of trapdoor permutation for Rabin.
 * This class wraps the crypto++ implementation of Rabin permutation.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public final class CryptoPpRabinPermutation extends TrapdoorPermutationAbs implements RabinPermutation {

	private long tpPtr; //pointer to the Rabin native object 
	
	// native functions. These functions are implemented in the CryptoPPJavaInterface dll using the JNI.
	
	//initializes Rabin permutation with public and private keys
	private native long initRabinPublicPrivate(byte[] mod, byte[] r, byte[] s, byte[] p, byte[] q, byte[] u);
	//initializes Rabin permutation with public key
	private native long initRabinPublic(byte[] mod, byte[] r, byte[] s);
	////initializes Rabin permutation randomly
	private native long initRabinRandomly(int numBits);
	
	//returns the algorithm name - rabin
	private native String loadRabinName(long ptr);
	//returns the modulus
	private native byte[] getRabinModulus(long ptr);
	//returns p
	private native byte[] getPrime1(long ptr);
	//returns q
	private native byte[] getPrime2(long ptr);
	//returns inversePModQ (u)
	private native byte[] getinversePModQ(long ptr);
	//returns the QuadraticResidueModPrime1 (r)
	private native byte[]getQuadraticResidueModPrime1(long ptr);
	//returns the QuadraticResidueModPrime1 (s)
	private native byte[]getQuadraticResidueModPrime2(long ptr);
	//checks if the given element value is valid for this Rabin permutation
	private native boolean checkRabinValidity(long value, long tpPtr);
	
	//computes Rabin permutation
	private native long computeRabin(long tpr, long x);
	//inverts Rabin permutation
	private native long invertRabin(long ptr, long y);

	//deletes the native object
	private native void deleteRabin(long ptr);
	
	

	/** 
	 * Initializes this Rabin permutation with public and private keys
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException if the given keys are invalid for Rabin permutation
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
			
		if (!(publicKey instanceof RabinPublicKey) || !(privateKey instanceof RabinPrivateKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
		
		RabinPublicKey pub = (RabinPublicKey)publicKey;
		RabinPrivateKey priv = (RabinPrivateKey)privateKey;
		
		//gets all the parameters
		BigInteger r, s, p, q, u;
		modulus = pub.getModulus();
		r = pub.getQuadraticResidueModPrime1();
		s = pub.getQuadraticResidueModPrime2();
		p = priv.getPrime1();
		q = priv.getPrime2();
		u = priv.getInversePModQ();
		
	
		//init the rabin native object
		tpPtr = initRabinPublicPrivate(modulus.toByteArray(), r.toByteArray(), s.toByteArray(), 
					 p.toByteArray(), q.toByteArray(), u.toByteArray());
		
		//calls the parent init that sets the keys
		super.setKey(publicKey, privateKey);
			
	}

	/** 
	 * Initializes this Rabin permutation with public key.
	 * After this initialization, this object can do compute but not invert.
	 * This initialization is for user that wants to encrypt a message using the public key but deosn't want to decrypt a message.
	 * @param publicKey - public key
	 * @throws InvalidKeyException if the given key is invalid for this Rabin permutation
	 */
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
			
		if (!(publicKey instanceof RabinPublicKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
		
		RabinPublicKey pub = (RabinPublicKey)publicKey;
		//get the n, r, s parameters
		BigInteger r,s;
		modulus = pub.getModulus();
		r = pub.getQuadraticResidueModPrime1();
		s = pub.getQuadraticResidueModPrime2();
		
		//init the rabin native object
		tpPtr = initRabinPublic(modulus.toByteArray(), r.toByteArray(), s.toByteArray());
		
		//calls the parent init that sets the key
		super.setKey(publicKey);
		
	}
	
	/** 
	 * @return the algorithm name - Rabin
	 */
	public String getAlgorithmName() {
		
		return loadRabinName(tpPtr);
	}
	
	/** 
	 * Generates Rabin private and public keys
	 * @param params RabinKeyGenParameterSpec
	 * @throws InvalidParameterSpecException if params are invalid parameter spec
	 */
	public KeyPair generateKey(AlgorithmParameterSpec params) throws InvalidParameterSpecException {

		if (!(params instanceof RabinKeyGenParameterSpec)) {
			throw new InvalidParameterSpecException("AlgorithmParameterSpec type doesn't match the trapdoor permutation type");
		}
		
		//gets the modulus bits size
		int numBits = ((RabinKeyGenParameterSpec) params).getKeySize();

		//init the Rabin native object
		long tpPtr = initRabinRandomly(numBits);
		
		//sets the modN
		BigInteger mod = new BigInteger(getRabinModulus(tpPtr));
		BigInteger p = new BigInteger(getPrime1(tpPtr));
		BigInteger q = new BigInteger(getPrime2(tpPtr));
		BigInteger u = new BigInteger(getinversePModQ(tpPtr));
		BigInteger r = new BigInteger(getQuadraticResidueModPrime1(tpPtr));
		BigInteger s = new BigInteger(getQuadraticResidueModPrime2(tpPtr));
		
		ScRabinPublicKey publicKey = new ScRabinPublicKey(mod, r, s);
		ScRabinPrivateKey privateKey = new ScRabinPrivateKey(mod, p, q, u);
		
		KeyPair pair = new KeyPair(publicKey, privateKey);
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
	 * Computes the Rabin permutation on the given TPElement 
	 * @param tpEl - the input for the computation
	 * @return - the result element
	 * @throws - IllegalArgumentException if the given element is not CryptoPpRabinElement
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException{
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		if (!(tpEl instanceof CryptoPpRabinElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		// gets the pointer for the native object
		long elementP = ((CryptoPpRabinElement)tpEl).getPointerToElement(); 
		
		//calls the native function
		long result = computeRabin(tpPtr, elementP); 
		
		//creates and initializes RabinElement with the result
		CryptoPpRabinElement returnEl = new CryptoPpRabinElement(result);
		
		return returnEl; // returns the result TPElement
	}
	
	/** 
	 * Inverts the Rabin permutation on the given element 
	 * @param tpEl - the input to invert
	 * @return - the result element
	 * @throws KeyException 
	 * @throws - IllegalArgumentException if the given element is not CryptoPpRabinElement
	 */
	public TPElement invert(TPElement tpEl) throws IllegalArgumentException, KeyException{
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		//If the key set was only the public key and not the private key - can't do the invert, throw exception.
		if (privKey == null && pubKey!=null){
			throw new KeyException("in order to invert a RabinElement, this object must be initialized with private key");
		}
		
		if (!(tpEl instanceof CryptoPpRabinElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		// get the pointer for the native object
		long elementP = ((CryptoPpRabinElement)tpEl).getPointerToElement(); 

		//calls the native function
		long result = invertRabin(tpPtr, elementP); 

		
		//creates and initializes RabinElement with the result
		CryptoPpRabinElement returnEl = new CryptoPpRabinElement(result);

		return returnEl; // returns the result TPElement
	}

	
	/** 
	 * Checks if the given element is valid for this Rabin permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * There are three possible validity values: 
	 * VALID (it is an element)
	 * NOT_VALID (it is not an element)
	 * DON’T_KNOW (there is not enough information to check if it is an element or not)  
	 * @throws - IllegalStateException if a key has not been set
	 * @throws - IllegalArgumentException if the given element is not CryptoPpRabinElement
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException, IllegalStateException{

		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		//If the key set was only the public key and not the private key - can't check if this candidate is or not a valid element. Therefore, return TPElValidity.DONT_KNOW
		if (privKey == null && pubKey!=null){
			return TPElValidity.DONT_KNOW;
		}
		
		if (!(tpEl instanceof CryptoPpRabinElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}

		BigInteger value = ((CryptoPpRabinElement)tpEl).getElement();

		//if the value is not between 1 to (mod n) - 1 then there is no need to continue checking, just return NOT_VALID
		if(!((value.compareTo(BigInteger.ZERO))>0) && (value.compareTo(modulus)<0)) {
			return TPElValidity.NOT_VALID;
		}
		TPElValidity validity = null;
		long elementP = ((CryptoPpRabinElement)tpEl).getPointerToElement(); 

		//Validity is checked in the native code:
		if(checkRabinValidity(elementP, tpPtr)){
			validity = TPElValidity.VALID;
			//if the value is invalid returns NOT_VALID 
		} else {
			validity = TPElValidity.NOT_VALID;
		}
		
		return validity;
	}
	
	/** 
	 * This function generates a random Rabin element while ensuring that the value obtained is relatively prime to the modulus.
	 * @return TPElement - the created element
	 */
	public TPElement generateRandomTPElement(){
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		return new CryptoPpRabinElement(modulus);
		
	}
	
	

	/**
	 * Creates a Rabin Element based on the x value if the x value is valid for this permutation.<p>
	 * If it succeeds, it is guaranteed that the element returned is a valid Rabin Element for this Rabin permutation instance.
	 * @param x an integer value to set as the value of the Rabin element
	 * @return a Rabin Element based on the cryptoPP library suitable to use with this permutation.  
	 * @throws IllegalStateException if keys aren't set
	 * @throws IllegalArgumentException if the x value is not a valid value for this trapdoor permution
	 * @throws ScapiRuntimeException if there is not enough information (trapdoor) to create this element
	 */
	public TPElement generateTPElement(BigInteger x) throws IllegalArgumentException {
		//This function creates the corresponding CryptoPpRabinElement by calling the CryptoPpRabinElement constructor that gets the modulus and a value x (BigInteger) as arguments. 
		//It then checks that the x value is legal for the trapdoor permutation it belongs to, that is, it is in the range and it has a square root in Zn. 
		//If so, it creates the object. Else, it throws IllegalArgumentException.
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		CryptoPpRabinElement tpElement = new CryptoPpRabinElement(modulus,x);
		TPElValidity validity = isElement(tpElement);
		
		if(validity == TPElValidity.NOT_VALID)
			throw new IllegalArgumentException("The x value " + x + " is not a valid value for this trapdoor permutation");
		if( validity == TPElValidity.DONT_KNOW)
			throw new ScapiRuntimeException("There is not enough information (trapdoor) to create this element");
		
		//If we got here then the element is valid, return it!
		return tpElement;
	}
	
	/**
	 * This function returns a "possible" RabinElement based on the x value.<p>
	 * No validity checks are performed on the x value so it is the caller's responsibility to make sure that the x value passed is a valid one.<p>
	 * It is possible to call the isElement(TpElement) function on the object returned by this function if eventually validity checks are needed.
	 * @param x an integer value to set as the value of the Rabin element
	 * @return a possible Rabin Element
	 * @throws IllegalStateException if keys aren't set.
	 */
	public TPElement generateUncheckedTPElement(BigInteger x) {
		return new CryptoPpRabinElement(null,x);
		
	}
	
	
	/**
	 * deletes the native Rabin object
	 */
	protected void finalize() throws Throwable {
		
		//deletes from the dll the dynamic allocation of the Rabin permutation.
		deleteRabin(tpPtr);
		
		super.finalize();
	}
	
	//loads the dll
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }

	
}
