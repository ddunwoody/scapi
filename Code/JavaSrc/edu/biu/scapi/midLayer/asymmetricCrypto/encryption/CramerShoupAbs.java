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


package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.ScapiRuntimeException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScCramerShoupPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScCramerShoupPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScCramerShoupPublicKey.ScCramerShoupPublicKeySendableData;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupCiphertext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.securityLevel.CollisionResistant;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

public abstract class CramerShoupAbs implements CramerShoupDDHEnc{

	protected DlogGroup dlogGroup;				// Underlying DlogGroup.
	protected CryptographicHash hash;				// Underlying hash function.
	protected CramerShoupPublicKey publicKey;
	protected CramerShoupPrivateKey privateKey;
	protected SecureRandom random;
	protected BigInteger qMinusOne; 				// Saved to avoid many calculations.
	private boolean isKeySet;
	
	/**
	 * Default constructor. It uses a default Dlog group and CryptographicHash.
	 */
	public CramerShoupAbs()  {
		try {
			doConstruct(new CryptoPpDlogZpSafePrime("1024"), new CryptoPpSHA1(), new SecureRandom());
		} catch (SecurityLevelException e) {
			// Shouldn't occur since the DlogGroup is DDH - secure.
		}
	}

	/**
	 * Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.
	 * @param dlogGroup underlying DlogGroup to use.
	 * @param hash underlying hash to use.
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	public CramerShoupAbs(DlogGroup dlogGroup, CryptographicHash hash) throws SecurityLevelException{
		doConstruct(dlogGroup, hash, new SecureRandom());
	}

	/**
	 * Constructor that lets the user choose the underlying dlog, hash and source of randomness.<p>
	 * The underlying Dlog group has to have DDH security level.<p>
	 * The underlying Hash function has to have CollisionResistant security level.
	 * @param dlogGroup underlying DlogGroup to use.
	 * @param hash underlying hash to use.
	 * @param random source of randomness.
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	public CramerShoupAbs(DlogGroup dlogGroup, CryptographicHash hash, SecureRandom random) throws SecurityLevelException{
		doConstruct(dlogGroup, hash, random);
	}

	/**
	 * Sets the given members.
	 * @param dlogGroup
	 * @param hash
	 * @param random
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	private void doConstruct(DlogGroup dlogGroup, CryptographicHash hash,
			SecureRandom random) throws SecurityLevelException {
		//The Cramer-Shoup encryption scheme must work with a Dlog Group that has DDH security level
		//and a Hash function that has CollisionResistant security level. If any of this conditions is not 
		//met then cannot construct an object of type Cramer-Shoup encryption scheme; therefore throw exception.
		if(!(dlogGroup instanceof DDH)){
			throw new SecurityLevelException("The Dlog group has to have DDH security level");
		}
		if(!(hash instanceof CollisionResistant)){
			throw new SecurityLevelException("The hash function has to have CollisionResistant security level");
		}
		// Everything is correct, then sets the member variables and creates object.
		this.dlogGroup = dlogGroup;
		qMinusOne = dlogGroup.getOrder().subtract(BigInteger.ONE);
		this.hash = hash;
		this.random = random;
	}

	/**
	 * Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.
	 * @param dlogGroupName name of the underlying dlog group
	 * @param hashName name of the underlying hash function
	 * @throws FactoriesException if one of the algorithm's names is not supported
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	public CramerShoupAbs(String dlogGroupName, String hashName) throws FactoriesException, SecurityLevelException{
		// Creates a dlog group object and a cryptographic hash object with relevant factories, and then uses regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogGroupName), CryptographicHashFactory.getInstance().getObject(hashName));
	}
	
	/**
	 * Constructor that lets the user choose the underlying dlog, hash and source of randomness.
	 * @param dlogGroupName name of the underlying dlog group.
	 * @param hashName name of the underlying hash function.
	 * @param randNumGenAlg random number generation algorithm.
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	public CramerShoupAbs(String dlogGroupName, String hashName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException, SecurityLevelException{
		//Creates a dlog group object and a cryptographic hash object with relevant factories.
		//Creates a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
		//Then uses regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogGroupName), CryptographicHashFactory.getInstance().getObject(hashName), SecureRandom.getInstance(randNumGenAlg));
	}
	
	
	/**
	 * This function sets the Public\Private key.
	 * @param publicKey the public key has to be of type <link>CramerShoupPublicKey<link>.
	 * @param privateKey the private key has to be of type <link>CramerShoupPrivateKey<link>.
	 * @throws InvalidKeyException if the keys are not instances of CramerShoup keys.
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException{
		
		//Public key should be Cramer-Shoup public key.
		if(!(publicKey instanceof CramerShoupPublicKey)){
			throw new InvalidKeyException("The public key must be of type CramerShoupPublicKey");
		}
		//Sets the public key.
		this.publicKey = (CramerShoupPublicKey) publicKey;

		//Private key should be Cramer Shoup private key.	
		if(privateKey == null){
			//If the private key in the argument is null then this instance's private key should be null.  
			this.privateKey = null;
		}else{
			if(!(privateKey instanceof CramerShoupPrivateKey)){
				throw new InvalidKeyException("The private key must be of type CramerShoupPrivatKey");
			}
			//Computes an optimization of the private key.
			initPrivateKey(privateKey);
		}
		isKeySet = true;
	}
	
	protected abstract void initPrivateKey(PrivateKey privateKey);

	/**
	 * This function sets only the Public key.
	 * Setting only the public key the user can encrypt messages but can not decrypt messages.
	 * @param publicKey the public key has to be of type <link>CramerShoupPublicKey<link>.
	 * @throws InvalidKeyException if the key is not instance of CramerShoup key.
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException{
		setKey(publicKey, null);
	}

	/**
	 * Generates pair of CramerShoupPublicKey and CramerShoupPrivateKey.
	 * @return KeyPair holding the CramerShoup public and private keys
	 */
	public KeyPair generateKey() {
		/*
		 * 	Given a Dlog Group (G, q, g) do: 
			Choose two distinct, random generators g1, g2. (how?)
			Choose five random values (x1, x2, y1, y2, z) in Zq.
			Compute c = g_1^(x1 ) g_2^(x2 ), d= g_1^(y1 ) g_2^(y2 ), h= g1^z.
			Set the public key part of the key pair to be c, d, h. 
			Set the private key part of the key pair to be x1, x2, y1, y2, z. 
			Return the key pair.
		 */
		GroupElement generator1 = null;
		GroupElement generator2 = null;
		do {
			generator1 = dlogGroup.createRandomGenerator();
			generator2 = dlogGroup.createRandomGenerator();
		}while(generator1.equals(generator2));
		
		//Chooses five random values (x1, x2, y1, y2, z) in Zq.
		BigInteger x1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger x2 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger y1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger y2 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger z = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		
		//Calculates c, d and h:
		GroupElement c = null;
		GroupElement d = null; 
		GroupElement h = null;
		
		try {
			c = dlogGroup.multiplyGroupElements(dlogGroup.exponentiate(generator1,x1), dlogGroup.exponentiate(generator2, x2));
			d = dlogGroup.multiplyGroupElements(dlogGroup.exponentiate(generator1,y1), dlogGroup.exponentiate(generator2, y2));
			h = dlogGroup.exponentiate(generator1, z);
		} catch (IllegalArgumentException e) {
			//Shouldn't occur since the generators were generated by the DlogGroup.
			e.printStackTrace();
		}
		
		CramerShoupPublicKey publicKey = new ScCramerShoupPublicKey(c, d, h, generator1, generator2);
		
		CramerShoupPrivateKey privateKey = new ScCramerShoupPrivateKey(x1, x2, y1, y2, z);
		
		KeyPair keyPair = new KeyPair(publicKey, privateKey);
		
		return keyPair;
	}
	
	/**
	 * This function is not supported for this encryption scheme, since there is no need for parameters to generate a CramerShoup key pair.
	 * @throws UnsupportedOperationException
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//No need for parameters to generate an Cramer-Shoup key pair. Therefore this operation is not supported.
		throw new UnsupportedOperationException("To generate Cramer-Shoup keys use the other generateKey function");
	}
	
	
	/**
	 * 
	 * This function does NOT create a new private key. It reconstructs a private key that has been previously serialized.
	 * @param data
	 * @return
	 * @deprecated As of SCAPI-V1-0-2-2 use reconstructPrivateKey(KeySendableData data)
	 */
	@Deprecated public CramerShoupPrivateKey generatePrivateKey(KeySendableData data){
		if(! (data instanceof CramerShoupPrivateKey))
				throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type CramerShoupPrivateKey");
		return (CramerShoupPrivateKey)data;
	}

	/**
	 * 
	 * @data The KeySendableData object has to be of type CramerShoupPrivateKey
	 */
	public CramerShoupPrivateKey reconstructPrivateKey(KeySendableData data){
		if(! (data instanceof CramerShoupPrivateKey))
				throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type CramerShoupPrivateKey");
		return (CramerShoupPrivateKey)data;
	}

	
	/**
	 * This function does NOT create a new public key. It reconstructs a public key that has been previously serialized.
	 * @param data
	 * @return
	 * @deprecated As of SCAPI-V1-0-2-2 use reconstructPublicKey(KeySendableData data)
	 */
	@Deprecated public CramerShoupPublicKey generatePublicKey(KeySendableData data){
		if(! (data instanceof ScCramerShoupPublicKeySendableData))
				throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type ScCramerShoupPublicKeySendableData");
		ScCramerShoupPublicKeySendableData data1 = (ScCramerShoupPublicKeySendableData)data;
		GroupElement c = dlogGroup.generateElement(true, data1.getC());
		GroupElement d = dlogGroup.generateElement(true, data1.getD());
		GroupElement h = dlogGroup.generateElement(true, data1.getH());
		GroupElement g1 = dlogGroup.generateElement(true, data1.getG1());
		GroupElement g2 = dlogGroup.generateElement(true, data1.getG2());
		
		return new ScCramerShoupPublicKey(c,d,h,g1,g2);
	}
	
	/**
	 * @data The KeySendableData object has to be of type ScCramerShoupPublicKeySendableData
	 */
	public CramerShoupPublicKey reconstructPublicKey(KeySendableData data){
		if(! (data instanceof ScCramerShoupPublicKeySendableData))
				throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type ScCramerShoupPublicKeySendableData");
		ScCramerShoupPublicKeySendableData data1 = (ScCramerShoupPublicKeySendableData)data;
		GroupElement c = dlogGroup.reconstructElement(true, data1.getC());
		GroupElement d = dlogGroup.reconstructElement(true, data1.getD());
		GroupElement h = dlogGroup.reconstructElement(true, data1.getH());
		GroupElement g1 = dlogGroup.reconstructElement(true, data1.getG1());
		GroupElement g2 = dlogGroup.reconstructElement(true, data1.getG2());
		
		return new ScCramerShoupPublicKey(c,d,h,g1,g2);
	}
	
	/**
	 * @deprecated Instead use reconstructPublicKey and reconstructPrivateKey. 
	 * @param publicKeyData
	 * @param privateKeyData
	 * @return
	 */
	@Deprecated public KeyPair generateKeyPair(KeySendableData publicKeyData, KeySendableData privateKeyData){
		if(! (publicKeyData instanceof ScCramerShoupPublicKeySendableData) || (! (privateKeyData instanceof ScCramerShoupPrivateKey)))
			throw new IllegalArgumentException("wrong type of KeySendableData");
		
		return new KeyPair(generatePublicKey(publicKeyData), generatePrivateKey(privateKeyData));
	}
	
	@Override
	public boolean isKeySet() {
		return isKeySet;
	}
	
	/**
	 * Returns the PublicKey of this CramerShoup encryption scheme.
	 * This function should not be used to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the CramerShoupPublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey(){
		if (!isKeySet()){
			throw new IllegalStateException("no PublicKey was set");
		}
		
		return publicKey;
	}

	/**
	 * @return the name of this AsymmetricEnc - CramerShoup and the underlying DlogGroup it uses.
	 */
	@Override
	public String getAlgorithmName() {
		return "CramerShoup/"+dlogGroup.getGroupType();
	}
	
	/**
	 * Encrypts the given plaintext using this Cramer Shoup encryption scheme.
	 * @param plaintext message to encrypt. MUST be an instance of GroupElementPlaintext.
	 * @return Ciphertext the encrypted plaintext.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext is not instance of GroupElementPlaintext.
	 */
	@Override
	public AsymmetricCiphertext encrypt(Plaintext plaintext){
		// If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		/*
		 * 	Choose a random  r in Zq<p>
		 *	Calculate 	u1 = g1^r<p>
		 *         		u2 = g2^r<p>
		 *         		e = (h^r)*msgEl<p>
		 *	Convert u1, u2, e to byte[] using the dlogGroup<P>
		 *	Compute alpha  - the result of computing the hash function on the concatenation u1+ u2+ e.<>
		 *	Calculate v = c^r * d^(r*alpha)<p>
		 *	Create and return an CramerShoupCiphertext object with u1, u2, e and v.
		 */
		
		//Choose the random r.
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		return encrypt(plaintext, r);
	}
	
	/**
	 * Calculates h^r
	 * @param r a random value.
	 * @return the calculated value.
	 */
	protected GroupElement calcHExpR(BigInteger r) {
		return dlogGroup.exponentiate(publicKey.getH(), r);
	}

	/**
	 * Calculates u2 = g2^r
	 * @param r a random value.
	 * @return the calculated u2.
	 */
	protected GroupElement calcU2(BigInteger r) {
		return dlogGroup.exponentiate(publicKey.getGenerator2(), r);
	}

	/**
	 * Calculates u1 = g1^r
	 * @param r a random value.
	 * @return the calculated u1.
	 */
	protected GroupElement calcU1(BigInteger r) {
		return dlogGroup.exponentiate(publicKey.getGenerator1(), r);
	}
	
	/**
	 * Recieves three byte arrays and calculates the hash function on their concatenation.
	 * @param u1ToByteArray
	 * @param u2ToByteArray
	 * @param eToByteArray
	 * @return the result of hash(u1ToByteArray+u2ToByteArray+eToByteArray)
	 */
	protected byte[] calcAlpha(byte[] u1ToByteArray, byte[] u2ToByteArray,
			byte[] eToByteArray) {
		//Concatenates u1, u2 and e into msgToHash.
		int lengthOfMsgToHash =  u1ToByteArray.length + u2ToByteArray.length + eToByteArray.length;
		byte[] msgToHash = new byte[lengthOfMsgToHash];
		System.arraycopy(u1ToByteArray, 0, msgToHash, 0, u1ToByteArray.length);
		System.arraycopy(u2ToByteArray, 0, msgToHash, u1ToByteArray.length, u2ToByteArray.length);
		System.arraycopy(eToByteArray, 0, msgToHash, u2ToByteArray.length+u1ToByteArray.length, eToByteArray.length);
		
		//Calculates the hash of msgToHash.
		
		//Calls the update function in the Hash interface.
		hash.update(msgToHash, 0, msgToHash.length);

		//Gets the result of hashing the updated input.
		byte[] alpha = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(alpha, 0);
		return alpha;
	}
	
	/**
	 * calculate the v value of the encryption.
	 * v = c^r * d^(r*alpha).
	 * @param r a random value
	 * @param alpha the value returned from the hash calculation.
	 * @return the calculated value v.
	 */
	protected GroupElement calcV(BigInteger r, byte[] alpha) {
		GroupElement cExpr = dlogGroup.exponentiate(publicKey.getC(), r);
		BigInteger q = dlogGroup.getOrder();
		BigInteger rAlphaModQ = (r.multiply(new BigInteger(alpha))).mod(q);
		GroupElement dExpRAlpha = dlogGroup.exponentiate(publicKey.getD(), rAlphaModQ);
		GroupElement v = dlogGroup.multiplyGroupElements(cExpr, dExpRAlpha);
		return v;
	}
	
	/**
	 * This function is called from the decrypt function. It Validates that the given cipher is correct.
	 * If the function find that the cipher is not valid, it throws a ScapiRuntimeException.
	 * @param cipher to validate.
	 * @param alpha parameter needs to validation.
	 * @throws ScapiRuntimeException if the given cipher is not valid.
	 */
	protected void checkValidity(CramerShoupCiphertext cipher,
			byte[] alpha) {
		BigInteger q = dlogGroup.getOrder();
		//Calculates u1^(x1+y1*alpha).
		BigInteger exponent1 = privateKey.getPrivateExp1().add((privateKey.getPrivateExp3().multiply(new BigInteger(alpha)))).mod(q);
		GroupElement t1 = dlogGroup.exponentiate(cipher.getU1(),exponent1);
		//Calculates u2^(x2+y2*alpha).
		BigInteger exponent2 = privateKey.getPrivateExp2().add((privateKey.getPrivateExp4().multiply(new BigInteger(alpha)))).mod(q);
		GroupElement t2 = dlogGroup.exponentiate(cipher.getU2(),exponent2);

		//Verifies that their multiplication is equal to v. If not, throws exception.
		GroupElement mult = dlogGroup.multiplyGroupElements(t1, t2);
		
		if (!mult.equals(cipher.getV())){
			throw new ScapiRuntimeException("Error! Cannot proceed with decryption"); 
		}
	}
}
