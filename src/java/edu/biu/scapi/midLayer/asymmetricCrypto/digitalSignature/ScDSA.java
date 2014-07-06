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


package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DSAPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DSAPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDSAPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDSAPublicKey;
import edu.biu.scapi.midLayer.signature.DSASignature;
import edu.biu.scapi.midLayer.signature.Signature;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.ZpElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECFp;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This class implements the DSA signature scheme.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScDSA implements DSABasedSignature{

	private DSAPublicKey publicKey;
	private DSAPrivateKey privateKey;
	private boolean isKeySet;						//Sets to false until setKey is called
	private CryptographicHash hash;					//The underlying hash to use
	private DlogGroup dlog;							//The underlying DlogGroup to use
	
	private SecureRandom random;
	private BigInteger qMinusOne;					//We keep this value to save unnecessary calculations.
	
	/**
	 * Default constructor. uses default implementations of CryptographicHash, DlogGroup and SecureRandom.
	 */
	public ScDSA(){
		//Sets the parameters with default values.
		try {
			construct(new CryptoPpSHA1(), new MiraclDlogECFp(), new SecureRandom());
		} catch (IOException e1) {
			// If there was a problem to create the properties file of elliptic curve, creates Dlog over Zp*.
			construct(new CryptoPpSHA1(), new CryptoPpDlogZpSafePrime(), new SecureRandom());
		}
		
	}
	
	/**
	 * Constructor that receives hash and dlog name and random number generation algorithm to use.
	 * @param hashName underlying hash to use.
	 * @param dlogName underlying dlogGroup to use.
	 * @throws FactoriesException if there is no hash with the given name.
	 */
	public ScDSA(String hashName, String dlogName) throws FactoriesException{
		//Creates hash, dlog and random and calls the extended constructor.
		this(CryptographicHashFactory.getInstance().getObject(hashName), DlogGroupFactory.getInstance().getObject(dlogName), new SecureRandom());
	}
	
	/**
	 * Constructor that receives hash and dlog name and random number generation algorithm to use.
	 * @param hashName underlying hash to use.
	 * @param dlogName underlying dlogGroup to use.
	 * @param randNumGenAlg random number generation algorithm to use.
	 * @throws FactoriesException if there is no hash with the given name.
	 * @throws NoSuchAlgorithmException if there is no random number generation algorithm.
	 */
	public ScDSA(String hashName, String dlogName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		//Creates hash, dlog and random and calls the extended constructor.
		this(CryptographicHashFactory.getInstance().getObject(hashName), DlogGroupFactory.getInstance().getObject(dlogName), SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Constructor that receives hash function and DlogGroup to use.
	 * @param hash underlying hash to use
	 * @param dlog underlying DlogGroup to use.
	 */
	public ScDSA(CryptographicHash hash, DlogGroup dlog) {
		//Creates SecureRandom object and calls the other constructor.
		this(hash, dlog, new SecureRandom());
	}
	
	/**
	 * Constructor that receives hash, dlog and secure random to use.
	 * @param hash underlying hash to use.
	 * @param dlog underlying DlogGroup to use.
	 * @param random secure random to use.
	 */
	public ScDSA(CryptographicHash hash, DlogGroup dlog, SecureRandom random){
		construct(hash, dlog, random);
	}
	
	private void construct(CryptographicHash hash, DlogGroup dlog, SecureRandom random){
		//Sets the parameters.
		this.hash = hash;
		this.dlog = dlog;
		qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		this.random = random;
	}
	
	/**
	 * Sets this DSA with public key and private key.
	 * @param publicKey should be an instance of DSAPublicKey.
	 * @param privateKey hould be an instance of DSAPrivateKey.
	 * @throws InvalidKeyException if the given keys are not instances of DSA keys.
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		//Key should be DSA keys.
		if(!(publicKey instanceof DSAPublicKey)){
			throw new InvalidKeyException("keys should be instances of DSA keys");
		}
		if(privateKey!= null && !(privateKey instanceof DSAPrivateKey)){
				throw new InvalidKeyException("keys should be instances of DSA keys");
		}
		
		//Sets the parameters.
		this.publicKey = (DSAPublicKey) publicKey;
		if (privateKey != null){
			this.privateKey = (DSAPrivateKey) privateKey;
		}
		
		isKeySet = true;
		
	}

	/**
	 * Sets this DSA with a public key.<p> 
	 * In this case the signature object can be used only for verification.
	 * @param publicKey should be an instance of DSAPublicKey.
	 * @throws InvalidKeyException if the given key is not an instance of DSAPublicKey.
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		//Calls the other setKey function with null private key.
		setKey(publicKey, null);
		
	}

	@Override
	public boolean isKeySet() {
		
		return isKeySet;
	}
	
	/**
	 * Returns the PublicKey of this RSA encryption scheme.
	 * This function should not be use to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the RSAPublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey(){
		if (!isKeySet()){
			throw new IllegalStateException("no PublicKey was set");
		}
		
		return publicKey;
	}

	/**
	 * @return this algorithm name - "DSA"
	 */
	@Override
	public String getAlgorithmName() {
		
		return "DSA";
	}

	/**
	 * Signs the given message.
	 * @param msg the byte array to sign.
	 * @param offset the place in the msg to take the bytes from.
	 * @param length the length of the msg.
	 * @return the signature from the msg signing.
	 * @throws KeyException if PrivateKey is not set.
	 * @throws ArrayIndexOutOfBoundsException if the given offset and length are wrong for the given message.
	 */
	@Override
	public Signature sign(byte[] msg, int offset, int length) throws KeyException {
		/*
		 * PSEUDO-CODE:
		 *  o	Choose a random k in Zq*
		 *  o	Calculate r = g^k mod q.  
		 *  o	If r = 0, start again with a different random k
		 *	o	Calculate e = H(m), and let z be the Lq leftmost bits of e, where Lq is the bit length of the group order q.
		 *	o	Calculate s = k^(-1)(z + xr) mod q
		 *	o	If s = 0, start again with a different random k
		 *	o	The signature is (r, s)
		 *
		 */
		
		//If there is no private key can not sign, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to sign a message, this object must be initialized with private key");
		}
		
		// Checks that the offset and length are correct.
		if ((offset > msg.length) || (offset+length > msg.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		BigInteger r = BigInteger.ZERO;
		BigInteger s = BigInteger.ZERO;
		BigInteger k = null;
		BigInteger q = dlog.getOrder();
		//If after calculation s is 0 - starts again with a different k.
		while(s.equals(BigInteger.ZERO)){
			
			//If after calculation r is 0 - starts again with a different k.
			while(r.equals(BigInteger.ZERO)){
				//Chooses a random value in Zq*.
				k = BigIntegers.createRandomInRange(BigInteger.ONE, qMinusOne, random);
				GroupElement generator = dlog.getGenerator();
				//Calculates h = g^x.
				GroupElement h = dlog.exponentiate(generator, k);
				//Gets the BigInteger value of the groupElement.
				r = getRFromGroupElement(h);
			}
			
			//Computes H(m) and return the left Lq bits of the result as BigInteger.
			BigInteger z = hashMsg(msg, offset, length);
			
			//Calculates k^(-1)(z + xr) mod q.
			BigInteger kInv = k.modInverse(q);
			BigInteger xr = (privateKey.getX()).multiply(r);
			s = (z.add(xr)).multiply(kInv);
			s = s.mod(q);
			
		}
		
		//Creates DSA signature with r, s.
		return new DSASignature(r,s);
	}

	/*
	 * Computes H(msg). Returns the left Lq bits of the result as BigInteger.
	 */
	private BigInteger hashMsg(byte[] msg, int offset, int length) {
		//Gets H(msg).
		hash.update(msg, offset, length);
		byte[] hashResult = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(hashResult, 0);
		
		int bitSize = dlog.getOrder().bitLength();
		byte[] e = new byte[bitSize];
		BigInteger z;
		//Gets the Lq bits of hashResult.
		if (hashResult.length > (bitSize/8)){
			System.arraycopy(hashResult, 0, e, 0, bitSize);
			//Gets the BI representation of e.
			z = new BigInteger(e);
		} else {
			//Gets the BI representation of the hash result.
			z = new BigInteger(hashResult);
		}
		
		return z;
	}
	
	/*
	 * Calculates the BigInteger value for the algorithm from the given groupElement.
	 * In case of Zp element, the value is the element itself modulus q.
	 * In case of EC point, the value is the x coordinate of the point modulus q.
	 */
	private BigInteger getRFromGroupElement(GroupElement element){
		BigInteger r = null;
		//In case of Zp element, r is the element itself.
		if (element instanceof ZpElement){
			r = ((ZpElement) element).getElementValue();
		}
		//In case of EC point, r is the x coordinate of the point.
		if (element instanceof ECElement){
			r = ((ECElement) element).getX();
		}
		
		//Calculates r mod q.
		r = r.mod(dlog.getOrder());
		
		return r;
	}

	/**
	 * Verifies the given signatures.
	 * @param signature to verify. Should be an instance of DSASignature.
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return true if the signature is valid. false, otherwise.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Signature does not match this signature scheme.
	 * @throws ArrayIndexOutOfBoundsException if the given offset and length are wrong for the given message.
	 */
	@Override
	public boolean verify(Signature signature, byte[] msg, int offset, int length) {
		/*
		 *  PSEUDO-CODE:
		 *  o	If r or s is not in Zq*, return false
		 *  o	Calculate w = s^(-1) mod q
		 *  o	Calculate e = H(m). Let z be the Lq leftmost bits of e.
		 *  o	Calculate u1 = zw mod q
		 *  o	Calculate u2 = rw mod q
		 *  o	Calculate v = g^u1*g^u2. In Zp case, calculate vVal = v mod q. In EC case, Let vVal be the x coordinate of v mod q
		 *  o	If r = vVal return true.
		 */
		
		//If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		
		if (!(signature instanceof DSASignature)){
			throw new IllegalArgumentException("Signature must be instance of DSASignature");
		}
		
		// Checks that the offset and length are correct.
		if ((offset > msg.length) || (offset+length > msg.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		//Gets r and s from the signature.
		BigInteger r = ((DSASignature) signature).getR();
		BigInteger s = ((DSASignature) signature).getS();
		BigInteger q = dlog.getOrder();
		
		//If r not in Zq returns false.
		if ((r.compareTo(BigInteger.ZERO) <= 0) || (r.compareTo(q) >= 0)){
			return false;
		}
		//If s not in Zq returns false.
		if ((s.compareTo(BigInteger.ZERO) <= 0) || (s.compareTo(q) >= 0)){
			return false;
		}
		
		//w = s^-1 mod q.
		BigInteger w = s.modInverse(q);
		
		//Computes H(m) and return the left Lq bits of the result as BigInteger.
		BigInteger z = hashMsg(msg, offset, length);
		
		//u1 = z*w mod q.
		BigInteger u1 = (z.multiply(w)).mod(q);
		//u2 = r*w mod q.
		BigInteger u2 = (r.multiply(w)).mod(q);
		
		//v = g^u1*g^u2.
		GroupElement leftElement = dlog.exponentiate(dlog.getGenerator(), u1);
		GroupElement rightElement = dlog.exponentiate(publicKey.getY(), u2);
		GroupElement v = dlog.multiplyGroupElements(leftElement, rightElement);
		//Gets the BigInteger value of the groupElement.
		BigInteger vBI = getRFromGroupElement(v);
		
		return r.equals(vBI);
		
	}

	/**
	 * This function is not supported in this class. 
	 * Use generateKey() instead.
	 * @throws UnsupportedOperationException
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		throw new UnsupportedOperationException("To generate keys for this DSA use generateKey() function");
	}

	/**
	 * Generates public and private keys for this DSA scheme.
	 * @return KeyPair holding the public and private keys. 
	 */
	@Override
	public KeyPair generateKey() {
		KeyPair pair = null;
		 
		//Chooses a random value in Zq*.
		BigInteger x = BigIntegers.createRandomInRange(BigInteger.ONE, qMinusOne, random);
		GroupElement generator = dlog.getGenerator();
		//Calculates h = g^x.
		GroupElement y = dlog.exponentiate(generator, x);
		//Creates an ScDSAPublicKey with y and ScDSAPrivateKey with x.
		ScDSAPublicKey publicKey = new ScDSAPublicKey(y);
		ScDSAPrivateKey privateKey = new ScDSAPrivateKey(x);
		//Creates a KeyPair with the created keys.
		pair = new KeyPair(publicKey, privateKey);
	
		return pair;
	}

	
}
