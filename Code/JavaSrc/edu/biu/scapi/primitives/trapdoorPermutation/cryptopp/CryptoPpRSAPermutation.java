/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.trapdoorPermutation.RSAPermutation;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElValidity;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutationAbs;

/**
 * Concrete class of trapdoor permutation of RSA.
 * This class wraps the crypto++ implementation of RSA permutation
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public final class CryptoPpRSAPermutation extends TrapdoorPermutationAbs implements RSAPermutation {

	private long tpPtr; //pointer to the RSA native object
	private SecureRandom random;
	
	// native functions. These functions are implemented in the CryptoPPJavaInterface dll using the JNI.
	
	//initializes RSA permutation with public and private keys
	private native long initRSAPublicPrivate(byte[] modulus, byte[] pubExponent, byte[] privExponent);
	//initializes RSA permutation with public and crt private keys
	private native long initRSAPublicPrivateCrt(byte[] modulus, byte[] pubExponent, byte[] privExponent, 
									   byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] crt);
	//initializes RSA permutation with public key
	private native long initRSAPublic(byte[] modulus, byte[] pubExponent);
	
	//returns the algorithm name - RSA
	private native String loadRSAName(long ptr);
	//checks if the given element value is valid for this RSA permutation
	private native boolean checkRSAValidity(long value, long ptr);
	
	//computes RSA permutation
	private native long computeRSA(long tpr, long x);
	//inverts RSA permutation
	private native long invertRSA(long ptr, long y);
	
	//deletes the native object
	private native void deleteRSA(long ptr);
	
	
	public CryptoPpRSAPermutation(){
		this(new SecureRandom());
	}
	
	public CryptoPpRSAPermutation(SecureRandom random){
		this.random = random;
	}
	
	public CryptoPpRSAPermutation(String randNumGenAlg) throws NoSuchAlgorithmException{
		this(SecureRandom.getInstance(randNumGenAlg));
	}
	
	
	/** 
	 * Initializes this RSA with public and private keys
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException if the given keys are not RAE keys
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
			
		if (!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
			
		/* gets the values of modulus (N), pubExponent (e), privExponent (d)*/
		BigInteger pubExponent = ((RSAPublicKey) publicKey).getPublicExponent();
		BigInteger privExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
		modN = ((RSAKey) publicKey).getModulus();
		
		//if private key is CRT private key
		if (privateKey instanceof RSAPrivateCrtKey)
		{
			//gets all the crt parameters
			RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
			BigInteger p = key.getPrimeP();
			BigInteger q = key.getPrimeQ();
			BigInteger dp = key.getPrimeExponentP();
			BigInteger dq = key.getPrimeExponentQ();
			BigInteger crt = key.getCrtCoefficient();
			
			//initializes the native object
			tpPtr = initRSAPublicPrivateCrt(modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray(), 
					p.toByteArray(), q.toByteArray(), dp.toByteArray(), dq.toByteArray(), crt.toByteArray());
			
		//if private key is key with N, e, d
		} else {
			
			//init the native object with the RSA parameters - n, e, d
			tpPtr = initRSAPublicPrivate(modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray());
		}
		
		//calls the parent init that sets the keys
		super.setKey(publicKey, privateKey);
		
	}

	/** 
	 * Initializes this RSA permutation with public key
	 * @param publicKey - public key
	 * @throws InvalidKeyException if the key is not RSA key
	 */
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
			
		if (!(publicKey instanceof RSAPublicKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
			
		RSAPublicKey pub = (RSAPublicKey) publicKey;
		BigInteger pubExponent = pub.getPublicExponent();
		modN = pub.getModulus();
		
		//init the native object with the RSA public parameters - n, e
		tpPtr = initRSAPublic(modN.toByteArray(), pubExponent.toByteArray());

		//calls the parent init
		super.setKey(publicKey);
	}

	/** 
	 * @return the algorithm name - RSA
	 */
	public String getAlgorithmName() {
		
		return loadRSAName(tpPtr);
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
	 * Computes the RSA permutation on the given TPElement
	 * @param tpEl - the input for the computation
	 * @return - the result element
	 * @throws - IllegalArgumentException if the given element is not RSA element
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException{
		
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		// gets the pointer for the native object
		long elementP = ((CryptoPpRSAElement)tpEl).getPointerToElement(); 
		
		//calls for the native function
		long result = computeRSA(tpPtr, elementP); 
		
		//creates and initializes CryptoPpRSAElement with the result
		CryptoPpRSAElement returnEl = new CryptoPpRSAElement(result);
		
		return returnEl; // returns the result TPElement
	}
	
	/**
	 * Inverts the RSA permutation on the given element 
	 * @param tpEl - the input to invert
	 * @return - the result 
	 * @throws - IllegalArgumentException
	 */
	public TPElement invert(TPElement tpEl) throws IllegalArgumentException{
		
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		//in case that the initialization was with public key and no private key - can't do the invert and returns null
		if (privKey == null && pubKey!=null)
			return null;
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		//gets the pointer for the native object
		long elementP = ((CryptoPpRSAElement)tpEl).getPointerToElement();
		
		//calls for the native function
		long result = invertRSA(tpPtr, elementP); 
		
		//creates and initialize CryptoPpRSAElement with the result
		CryptoPpRSAElement returnEl = new CryptoPpRSAElement(result);
		
		return returnEl; // returns the result TPElement
	}
	
	/** 
	 * Checks if the given element is valid for this RSA permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * There are three possible validity values: 
	 * VALID (it is an element)
	 * NOT_VALID (it is not an element)
	 * DON’T_KNOW (there is not enough information to check if it is an element or not)  
	 * @throws - IllegalArgumentException if the given element is invalid for this RSA permutation
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException{

		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		TPElValidity validity = null;
		long value = ((CryptoPpRSAElement)tpEl).getPointerToElement();
		
		//if the trapdoor permutation is unknown - returns DONT_KNOW 
		if (modN == null) {
			validity = TPElValidity.DONT_KNOW;
		
		//if the value is valid (between 1 to (mod n) - 1) returns VALID 
		} else if(checkRSAValidity(value, tpPtr)) {
			
			validity = TPElValidity.VALID;
		//if the value is invalid returns NOT_VALID 
		} else {
			validity = TPElValidity.NOT_VALID;
		}		
		
		//returns the correct TPElValidity
		return validity;
	}

	/** 
	 * creates a random CryptoPpRSAElement
	 * @return TPElement - the created random element 
	 */
	public TPElement generateRandomTPElement() {

		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		return new CryptoPpRSAElement(modN);
	}
	
	@Override
	public TPElement generateTPElement(BigInteger x) throws IllegalArgumentException {
		if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		
		return new CryptoPpRSAElement(modN, x, true);
	}
	
	public TPElement generateUncheckedTPElement(BigInteger x) throws IllegalArgumentException {
		/*if (!isKeySet()){
			throw new IllegalStateException("keys aren't set");
		}
		*/
		return new CryptoPpRSAElement(modN, x, false);
	}
	
	/**
	 * deletes the native RSA object
	 */
	protected void finalize() throws Throwable {
		
		//deletes from the dll the dynamic allocation of the RSA permutation.
		deleteRSA(tpPtr);
		
		super.finalize();
	}
	
	//loads the dll
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }

	
	
	
	
}
