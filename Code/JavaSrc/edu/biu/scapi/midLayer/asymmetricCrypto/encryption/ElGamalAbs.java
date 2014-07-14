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

import java.io.IOException;
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
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey.ScElGamalPublicKeySendableData;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECFp;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * Abstract class that implements some common functionality to all ElGamal types.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class ElGamalAbs implements ElGamalEnc{

	protected DlogGroup dlog;						//The underlying DlogGroup
	protected ElGamalPrivateKey privateKey;		//ElGamal private key (contains x)
	protected ElGamalPublicKey publicKey;			//ElGamal public key (contains h)
	protected SecureRandom random;				//Source of randomness
	private boolean isKeySet;
	protected BigInteger qMinusOne;				//We keep this value to save unnecessary calculations.
	
	
	/**
	 * Default constructor. Uses the default implementations of DlogGroup, CryptographicHash and SecureRandom.
	 */
	public ElGamalAbs() {
		
		try {
			createMembers(new MiraclDlogECFp("P-192"), new SecureRandom());
		} catch (IOException e) {
			try {
				createMembers(new CryptoPpDlogZpSafePrime(), new SecureRandom());
			} catch (SecurityLevelException e1) {
				// Shouldn't occur since the DlogGroup is DDH - secure.
			}
		} catch (SecurityLevelException e) {
			// Shouldn't occur since the DlogGroup is DDH - secure.
		}
	}

	/**
	 * Constructor that gets a DlogGroup and sets it to the underlying group.
	 * It lets SCAPI choose and source of randomness.
	 * @param dlogGroup underlying DlogGroup to use, it has to have DDH security level
	 * @throws SecurityLevelException if the Dlog Group is not DDH secure
	 */
	public ElGamalAbs(DlogGroup dlogGroup) throws SecurityLevelException {
		this(dlogGroup, new SecureRandom());
	}
	
	/**
	 * Constructor that gets a DlogGroup and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @param random source of randomness.
	 * @throws SecurityLevelException  if the Dlog Group is not DDH secure
	 */
	public ElGamalAbs(DlogGroup dlogGroup, SecureRandom random) throws SecurityLevelException {
		createMembers(dlogGroup, random);
	}
	
	private void createMembers(DlogGroup dlogGroup, SecureRandom random) throws SecurityLevelException{
		//The underlying dlog group must be DDH secure.
		if (!(dlogGroup instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		dlog = dlogGroup;
		qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		this.random = random;
	}
	
	/**
	 * Constructor that gets a DlogGroup name to create and sets it to the underlying group.
	 * Uses default implementation of SecureRandom.
	 * @param dlogName must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws SecurityLevelException  if the Dlog Group is not DDH secure
	 */
	public ElGamalAbs(String dlogName) throws FactoriesException, SecurityLevelException{
		//Create a dlog group object with relevant factory, and then use regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogName));
	}
	
	
	/**
	 * Constructor that gets a DlogGroup name to create and random number generator to use.
	 * @param dlogName must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws NoSuchAlgorithmException if the given random number generator is not supported.
	 * @throws SecurityLevelException  if the Dlog Group is not DDH secure
	 */
	public ElGamalAbs(String dlogName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException, SecurityLevelException{
		//Creates a dlog group object with relevant factory.
		//Creates a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
		//Then use regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogName), SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Initializes this ElGamal encryption scheme with (public, private) key pair.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be ElGamalPublicKey.
	 * @param privateKey should be ElGamalPrivateKey.
	 * @throws InvalidKeyException if the given keys are not instances of ElGamal keys.
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException{
		//Key should be ElGamalPublicKey.
		if(!(publicKey instanceof ElGamalPublicKey)){
			throw new InvalidKeyException("keys should be instances of ElGamal keys");
		}
		
		//Key should be ElGamalPrivateKey.
		if(privateKey!= null && !(privateKey instanceof ElGamalPrivateKey)){
			throw new InvalidKeyException("keys should be instances of ElGamal keys");
		}
		
		//Sets the keys.
		this.publicKey = (ElGamalPublicKey) publicKey;
		
		if (privateKey != null){
			//Computes an optimization of the private key.
			initPrivateKey(privateKey);
		}
		
		isKeySet = true;
	}
	
	protected abstract void initPrivateKey(PrivateKey privateKey);
	
	/**
	 * Initializes this ElGamal encryption scheme with public key.
	 * Setting only the public key the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @throws InvalidKeyException if the given key is not instances of ElGamalPuclicKey.
	 */
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		setKey(publicKey, null);
	}
	
	@Override
	public boolean isKeySet(){
		return isKeySet;
	}
	
	/**
	 * Returns the PublicKey of this ElGamal encryption scheme.
	 * This function should not be use to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the ElGamalPublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey(){
		if (!isKeySet()){
			throw new IllegalStateException("no PublicKey was set");
		}
		
		return publicKey;
	}
	
	/**
	 * @return the name of this AsymmetricEnc - ElGamal and the underlying dlog group type
	 */
	public String getAlgorithmName(){
		return "ElGamal/"+dlog.getGroupType();
	}
	
	/**
	 * Generates a KeyPair containing a set of ElGamalPublicKEy and ElGamalPrivateKey using the source of randomness and the dlog specified upon construction.
	 * @return KeyPair contains keys for this ElGamal object.
	 */
	public KeyPair generateKey() {
		
		//Chooses a random value in Zq.
		BigInteger x = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		GroupElement generator = dlog.getGenerator();
		//Calculates h = g^x.
		GroupElement h = dlog.exponentiate(generator, x);
		//Creates an ElGamalPublicKey with h and ElGamalPrivateKey with x.
		ScElGamalPublicKey publicKey = new ScElGamalPublicKey(h);
		ScElGamalPrivateKey privateKey = new ScElGamalPrivateKey(x);
		//Creates a KeyPair with the created keys.
		KeyPair pair = new KeyPair(publicKey, privateKey);
		return pair;
	}
	
	/**
	 * This function is not supported for this encryption scheme, since there is no need for parameters to generate an ElGamal key pair.
	 * @throws UnsupportedOperationException
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//No need for parameters to generate an El Gamal key pair. 
		throw new UnsupportedOperationException("To Generate ElGamal keys use the generateKey() function");
	}
	
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructPublicKey(edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData)
	 */
	@Override
	public PublicKey reconstructPublicKey(KeySendableData data) {
		if(! (data instanceof ScElGamalPublicKeySendableData))
			throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type ScElGamalPublicKeySendableData");
		ScElGamalPublicKeySendableData data1 = (ScElGamalPublicKeySendableData)data;
		GroupElement h = dlog.reconstructElement(true, data1.getC());
		return new ScElGamalPublicKey(h);
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructPrivateKey(edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData)
	 */
	@Override
	public PrivateKey reconstructPrivateKey(KeySendableData data) {
		if(! (data instanceof ElGamalPrivateKey))
			throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type ElGamalPrivateKey");
	return (ElGamalPrivateKey)data;
	}
	
	/**
	 * Encrypts the given message using ElGamal encryption scheme.
	 * 
	 * @param plaintext contains message to encrypt. The given plaintext must match this ElGamal type.
	 * @return Ciphertext containing the encrypted message.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext does not match this ElGamal type.
	 */
	public AsymmetricCiphertext encrypt(Plaintext plaintext) {
		// If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		/* 
		 * Pseudo-code:
		 * 	•	Choose a random  y <- Zq.
		 *	•	Calculate c1 = g^y mod p //Mod p operation are performed automatically by the group.
		 *	•	Calculate c2 = h^y * plaintext.getElement() mod p // For ElGamal on a GroupElement.
		 *					OR KDF(h^y) XOR plaintext.getBytes()  // For ElGamal on a ByteArray.
		 */
		//Chooses a random value y<-Zq.
		BigInteger y = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		return encrypt(plaintext, y);	
	}
	
	/**
	 * Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.<p>
	 * There are cases when the random value is used after the encryption, for example, in sigma protocol. 
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user 
	 * since this can cause problems when more than one value is being encrypt. 
	 * Instead, we decided to have an additional encrypt value that gets the random value from the user.
	 * 
	 * @param plaintext contains message to encrypt. The given plaintext must match this ElGamal type.
	 * @param r The random value to use in the encryption. 
	 * @return Ciphertext containing the encrypted message.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext does not match this ElGamal type.
	 */
	public AsymmetricCiphertext encrypt(Plaintext plaintext, BigInteger r) {
		
		/* 
		 * Pseudo-code:
		 *	•	Calculate c1 = g^r mod p //Mod p operation are performed automatically by the group.
		 *	•	Calculate c2 = h^r * plaintext.getElement() mod p // For ElGamal on a GroupElement.
		 *					OR KDF(h^r) XOR plaintext.getBytes()  // For ElGamal on a ByteArray.
		 */
		
		// If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		
		//Check that the r random value passed to this function is in Zq.
		if(!((r.compareTo(BigInteger.ZERO))>=0) && (r.compareTo(qMinusOne)<=0)) {
			throw new IllegalArgumentException("r must be in Zq");
		}
		
		//Calculates c1 = g^y and c2 = msg * h^y.
		GroupElement generator = dlog.getGenerator();
		GroupElement c1 = dlog.exponentiate(generator, r);
		GroupElement hy = dlog.exponentiate(publicKey.getH(), r);
		
		return completeEncryption(c1, hy, plaintext);
	}
	
	protected abstract AsymmetricCiphertext completeEncryption(GroupElement c1, GroupElement hy, Plaintext plaintext);
	
	
	
}
