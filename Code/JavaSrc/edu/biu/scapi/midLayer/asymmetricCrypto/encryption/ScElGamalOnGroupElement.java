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
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPrivateKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnGroupElementCiphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnGroupElementCiphertext.ElGamalOnGrElSendableData;
import edu.biu.scapi.midLayer.plaintext.GroupElementPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class performs the El Gamal encryption scheme that perform the encryption on a GroupElement. <P>
 * In some cases there are protocols that do multiple calculations and might want to keep working on a close group. 
 * For those cases we provide encryption on a group element. <P>
 * 
 * By definition, this encryption scheme is CPA-secure and Indistinguishable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScElGamalOnGroupElement extends ElGamalAbs implements AsymMultiplicativeHomomorphicEnc{
	
	/**
	 * Default constructor. Uses the default implementations of DlogGroup, CryptographicHash and SecureRandom.
	 */
	public ScElGamalOnGroupElement() {
		super();
	}

	/**
	 * Constructor that gets a DlogGroup and sets it to the underlying group.
	 * It lets SCAPI choose and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @throws SecurityLevelException 
	 */
	public ScElGamalOnGroupElement(DlogGroup dlogGroup) throws SecurityLevelException {
		super(dlogGroup, new SecureRandom());
	}
	/**
	 * Constructor that gets a DlogGroup and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @param random source of randomness.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 */
	public ScElGamalOnGroupElement(DlogGroup dlogGroup, SecureRandom random) throws SecurityLevelException {
		super(dlogGroup, random);
	}
	
	/**
	 * Constructor that gets a DlogGroup name to create and sets it to the underlying group.
	 * Uses default implementation of SecureRandom.
	 * @param dlogName must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level. 
	 */
	public ScElGamalOnGroupElement(String dlogName) throws FactoriesException, SecurityLevelException{
		super(dlogName);
	}
	
	
	/**
	 * Constructor that gets a DlogGroup name to create and random number generator to use.
	 * @param dlogName must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws NoSuchAlgorithmException if the given random number generator is not supported.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 */
	public ScElGamalOnGroupElement(String dlogName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException, SecurityLevelException{
		super(dlogName, randNumGenAlg);
	}
	

	/**
	 * ElGamal decrypt function can be optimized if, instead of using the x value in the private key as is, 
	 * we change it to be q-x, while q is the dlog group order.
	 * This function computes this changing and saves the new private value as the private key member.
	 * @param privateKey to change.
	 */
	protected void initPrivateKey(PrivateKey privateKey){
		//Gets the a value from the private key.
		BigInteger x = ((ElGamalPrivateKey) privateKey).getX();
		//Gets the q-x value.
		BigInteger xInv = dlog.getOrder().subtract(x);
		//Sets the q-x value as the private key.
		this.privateKey = new ScElGamalPrivateKey(xInv);
	}
	
	/**
	 * El-Gamal encryption scheme has a limit of the byte array length to generate a plaintext from.
	 * @return true. 
	 */
	public boolean hasMaxByteArrayLengthForPlaintext(){
		return true;
	}
	
	/**
	 * Returns the maximum size of the byte array that can be passed to generatePlaintext function. 
	 * This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	 * @return the maximum size of the byte array that can be passed to generatePlaintext function. 
	 */
	public int getMaxLengthOfByteArrayForPlaintext(){
		return dlog.getMaxLengthOfByteArrayForEncoding();
	}
	
	/**
	 * Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 * @throws IllegalArgumentException if the given message's length is greater than the maximum. 
	 */
	public Plaintext generatePlaintext(byte[] text){
		if (text.length > getMaxLengthOfByteArrayForPlaintext()){
			throw new IllegalArgumentException("the given text is too big for plaintext");
		}
		
		return new GroupElementPlaintext(dlog.encodeByteArrayToGroupElement(text));
	}
	
	/**
	 * Completes the encryption operation.
	 * @param plaintext contains message to encrypt. MUST be of type GroupElementPlaintext.
	 * @return Ciphertext of type ElGamalOnGroupElementCiphertext containing the encrypted message.
	 * @throws IllegalArgumentException if the given Plaintext is not an instance of GroupElementPlaintext.
	 */
	protected AsymmetricCiphertext completeEncryption(GroupElement c1, GroupElement hy, Plaintext plaintext){
		
		if (!(plaintext instanceof GroupElementPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of GroupElementPlaintext");
		}
	
		//Gets the element.
		GroupElement msgElement = ((GroupElementPlaintext) plaintext).getElement();
	
		GroupElement c2 = dlog.multiplyGroupElements(hy, msgElement);
		
		//Returns an ElGamalCiphertext with c1, c2.
		ElGamalOnGroupElementCiphertext cipher = new ElGamalOnGroupElementCiphertext(c1, c2);
		return cipher;
	}

	/**
	 * Decrypts the given ciphertext using ElGamal encryption scheme.
	 *
	 * @param cipher MUST be of type ElGamalOnGroupElementCiphertext contains the cipher to decrypt.
	 * @return Plaintext of type GroupElementPlaintext which containing the decrypted message.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given cipher is not instance of ElGamalOnGroupElementCiphertext.
	 */
	public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException {
		/*  
		 * Pseudo-code:
		 * 	•	Calculate s = ciphertext.getC1() ^ x^(-1) //x^(-1) is kept in the private key because of the optimization computed in the function initPrivateKey.
		 *	•	Calculate m = ciphertext.getC2() * s
		 */
		
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be ElGamal ciphertext.
		if (!(cipher instanceof ElGamalOnGroupElementCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of ElGamalOnGroupElementCiphertext");
		}

		ElGamalOnGroupElementCiphertext ciphertext = (ElGamalOnGroupElementCiphertext) cipher;
		//Calculates sInv = ciphertext.getC1() ^ x.
		GroupElement sInv = dlog.exponentiate(ciphertext.getC1(), privateKey.getX());
		//Calculates the plaintext element m = ciphertext.getC2() * sInv.
		GroupElement m = dlog.multiplyGroupElements(ciphertext.getC2(), sInv);
		
		//Creates a plaintext object with the element and returns it.
		return new GroupElementPlaintext(m);
	}

	/**
	 * Generates a byte array from the given plaintext. 
	 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has, 
	 * and therefore he is working on byte array.
	 * @param plaintext to generates byte array from. MUST be an instance of GroupElementPlaintext.
	 * @return the byte array generated from the given plaintext.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of GroupElementPlaintext.
	 */
	public byte[] generateBytesFromPlaintext(Plaintext plaintext){
		if (!(plaintext instanceof GroupElementPlaintext)){
			throw new IllegalArgumentException("plaintext should be an instance of GroupElementPlaintext");
		}
		GroupElement el = ((GroupElementPlaintext) plaintext).getElement();
		return dlog.decodeGroupElementToByteArray(el);
	}
	
	/**
	 * Calculates the ciphertext resulting of multiplying two given ciphertexts.
	 * Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
	 * 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	 */
	public AsymmetricCiphertext multiply(AsymmetricCiphertext cipher1, AsymmetricCiphertext cipher2) {
		
		//Choose a random value in Zq.
		BigInteger w = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Call the other function that computes the multiplication.
		return multiply(cipher1, cipher2, w);
	}

	/**
	 * Calculates the ciphertext resulting of multiplying two given ciphertexts.<P>
	 * Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.<p>
	 * 
	 * There are cases when the random value is used after the function, for example, in sigma protocol. 
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user 
	 * since this can cause problems when the multiply function is called more than one time. 
	 * Instead, we decided to have an additional multiply function that gets the random value from the user.
	 * 
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
	 * 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	 */
	@Override
	public AsymmetricCiphertext multiply(AsymmetricCiphertext cipher1, AsymmetricCiphertext cipher2, BigInteger w) {
		/* 
		 * Pseudo-Code:
		 * 	c1 = (u1, v1); c2 = (u2, v2) 
		 * 	COMPUTE u = g^w*u1*u2
		 * 	COMPUTE v = h^w*v1*v2
		 * 	OUTPUT c = (u,v)
		 */
		
		// If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		
		// Cipher1 and cipher2 should be ElGamal ciphertexts.
		if (!(cipher1 instanceof ElGamalOnGroupElementCiphertext) || !(cipher2 instanceof ElGamalOnGroupElementCiphertext)){
			throw new IllegalArgumentException("ciphertexts should be instance of ElGamalCiphertext");
		}
		ElGamalOnGroupElementCiphertext c1 = (ElGamalOnGroupElementCiphertext)cipher1;
		ElGamalOnGroupElementCiphertext c2 = (ElGamalOnGroupElementCiphertext)cipher2;
		
		//Gets the groupElements of the ciphers.
		GroupElement u1 = c1.getC1();
		GroupElement v1 = c1.getC2();
		GroupElement u2 = c2.getC1();
		GroupElement v2 = c2.getC2();
		
		if (!(dlog.isMember(u1)) || !(dlog.isMember(v1)) || !(dlog.isMember(u2)) || !(dlog.isMember(v2))){
			throw new IllegalArgumentException("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog.getGroupType());
		}
		
		//Check that the r random value passed to this function is in Zq.
		if(!((w.compareTo(BigInteger.ZERO))>=0) && (w.compareTo(qMinusOne)<=0)) {
			throw new IllegalArgumentException("the given random value must be in Zq");
		}
				
		//Calculates u = g^w*u1*u2.
		GroupElement gExpW = dlog.exponentiate(dlog.getGenerator(), w);
		GroupElement gExpWmultU1 = dlog.multiplyGroupElements(gExpW, c1.getC1());
		GroupElement u = dlog.multiplyGroupElements(gExpWmultU1, c2.getC1());
		
		//Calculates v = h^w*v1*v2.
		GroupElement hExpW = dlog.exponentiate(publicKey.getH(), w);
		GroupElement hExpWmultV1 = dlog.multiplyGroupElements(hExpW, c1.getC2());
		GroupElement v = dlog.multiplyGroupElements(hExpWmultV1, c2.getC2());
		
		return new ElGamalOnGroupElementCiphertext(u,v);
	}
	
	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 * @deprecated  As of SCAPI-V1-0-2-2 use reconstructCiphertext(AsymmetricCiphertextSendableData data)
	 */
	@Override
	@Deprecated public AsymmetricCiphertext generateCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof ElGamalOnGrElSendableData))
				throw new IllegalArgumentException("The input data has to be of type ElGamalOnGrElSendableData");
		ElGamalOnGrElSendableData data1 = (ElGamalOnGrElSendableData)data;
		GroupElement cipher1 = dlog.generateElement(true, data1.getCipher1());
		GroupElement cipher2 = dlog.generateElement(true, data1.getCipher2());	
		return new ElGamalOnGroupElementCiphertext(cipher1, cipher2);
	}
	
	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 */
	@Override
	public AsymmetricCiphertext reconstructCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof ElGamalOnGrElSendableData))
				throw new IllegalArgumentException("The input data has to be of type ElGamalOnGrElSendableData");
		ElGamalOnGrElSendableData data1 = (ElGamalOnGrElSendableData)data;
		GroupElement cipher1 = dlog.reconstructElement(true, data1.getCipher1());
		GroupElement cipher2 = dlog.reconstructElement(true, data1.getCipher2());	
		return new ElGamalOnGroupElementCiphertext(cipher1, cipher2);
	}
}
