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

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.*;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupOnGroupElementCiphertext;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupOnGroupElementCiphertext.CrShOnGroupElSendableData;
import edu.biu.scapi.midLayer.plaintext.GroupElementPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.*;
import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
 * Concrete class that implement Cramer-Shoup encryption scheme.
 * By definition, this encryption scheme is CCA-secure and NonMalleable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCramerShoupDDHOnGroupElement extends CramerShoupAbs {
	
	/**
	 * Default constructor. It uses a default Dlog group and CryptographicHash.
	 */
	public ScCramerShoupDDHOnGroupElement(){
		super();
	}

	/**
	 * Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.
	 * @param dlogGroup underlying DlogGroup to use, it has to have DDH security level
	 * @param hash underlying hash to use, has to have CollisionResistant security level
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	public ScCramerShoupDDHOnGroupElement(DlogGroup dlogGroup, CryptographicHash hash) throws SecurityLevelException{
		super(dlogGroup, hash);
	}

	/**
	 * Constructor that lets the user choose the underlying dlog, hash and source of randomness.
	 * @param dlogGroup underlying DlogGroup to use, it has to have DDH security level
	 * @param hash underlying hash to use, has to have CollisionResistant security level
	 * @param random source of randomness.
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	public ScCramerShoupDDHOnGroupElement(DlogGroup dlogGroup, CryptographicHash hash, SecureRandom random) throws SecurityLevelException{
		super(dlogGroup, hash, random);
	}

	/**
	 * Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.
	 * @param dlogGroupName name of the underlying dlog group, it has to have DDH security level
	 * @param hashName name of the underlying hash function, has to have CollisionResistant security level
	 * @throws FactoriesException if one of the algorithm's names is not supported
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	public ScCramerShoupDDHOnGroupElement(String dlogGroupName, String hashName) throws FactoriesException, SecurityLevelException{
		super(dlogGroupName, hashName);
	}
	
	/**
	 * Constructor that lets the user choose the underlying dlog, hash and source of randomness.
	 * @param dlogGroupName name of the underlying dlog group, it has to have DDH security level
	 * @param hashName name of the underlying hash function, has to have CollisionResistant security level
	 * @param randNumGenAlg random number generation algorithm.
	 * @throws SecurityLevelException if the Dlog Group or the Hash function do not meet the required Security Level
	 */
	public ScCramerShoupDDHOnGroupElement(String dlogGroupName, String hashName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException, SecurityLevelException{
		super(dlogGroupName, hashName, randNumGenAlg);
	}
	
	/**
	 * CramerShoup decrypt function can be optimized if, instead of using the x value in the private key as is, 
	 * we change it to be q-x, while q is the dlog group order.
	 * This function computes this changing and saves the new private value as the private key member.
	 * @param privateKey to change.
	 */
	protected void initPrivateKey(PrivateKey privateKey){
		CramerShoupPrivateKey key = (CramerShoupPrivateKey) privateKey;
		//Gets the z value from the private key.
		BigInteger z = key.getPrivateExp5();
		//Gets the q-z value.
		BigInteger xInv = dlogGroup.getOrder().subtract(z);
		//Sets the q-z value as the z in private key.
		this.privateKey = new ScCramerShoupPrivateKey(key.getPrivateExp1(), key.getPrivateExp2(), key.getPrivateExp3(), key.getPrivateExp4(), xInv);
	}
	
	/**
	 * Cramer-Shoup on GroupElement encryption scheme has a limit of the byte array length to generate a plaintext from.
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
		return dlogGroup.getMaxLengthOfByteArrayForEncoding();
	}
	
	/**
	 * Generates a Plaintext suitable to CramerShoup encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 * @throws IllegalArgumentException if the given message's length is greater than the maximum. 
	 */
	public Plaintext generatePlaintext(byte[] text){
		if (text.length > getMaxLengthOfByteArrayForPlaintext()){
			throw new IllegalArgumentException("the given text is too big for plaintext");
		}
		
		return new GroupElementPlaintext(dlogGroup.encodeByteArrayToGroupElement(text));
	}
	
	/**
	 * Encrypts the given plaintext using this CramerShoup encryption scheme and using the given random value.<p>
	 * There are cases when the random value is used after the encryption, for example, in sigma protocol. 
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user 
	 * since this can cause problems when more than one value is being encrypt. 
	 * Instead, we decided to have an additional encrypt value that gets the random value from the user.
	 * @param plainText message to encrypt
	 * @param r The random value to use in the encryption. 
	 * @param plaintext message to encrypt. MUST be an instance of GroupElementPlaintext.
	 * @return Ciphertext the encrypted plaintext.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext is not instance of GroupElementPlaintext.
	 */
	public AsymmetricCiphertext encrypt(Plaintext plaintext, BigInteger r){
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
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		if (!(plaintext instanceof GroupElementPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of GroupElementPlaintext");
		}
		GroupElement msgElement = ((GroupElementPlaintext) plaintext).getElement();
		
		//Check that the random value passed to this function is in Zq.
		if(!((r.compareTo(BigInteger.ZERO))>=0) && (r.compareTo(qMinusOne)<=0)) {
			throw new IllegalArgumentException("r must be in Zq");
		}
				
		GroupElement u1 = calcU1(r);
		GroupElement u2 = calcU2(r);
		GroupElement hExpr = calcHExpR(r);
		GroupElement e = dlogGroup.multiplyGroupElements(hExpr, msgElement);
		
		byte[] u1ToByteArray = dlogGroup.mapAnyGroupElementToByteArray(u1);
		byte[] u2ToByteArray = dlogGroup.mapAnyGroupElementToByteArray(u2);
		byte[] eToByteArray = dlogGroup.mapAnyGroupElementToByteArray(e);
		
		//Calculates the hash(u1 + u2 + e).
		byte[] alpha = calcAlpha(u1ToByteArray, u2ToByteArray, eToByteArray);
		
		//Calculates v = c^r * d^(r*alpha).
		GroupElement v = calcV(r, alpha); 
		
		//Creates and return an CramerShoupCiphertext object with u1, u2, e and v.
		CramerShoupOnGroupElementCiphertext cipher = new CramerShoupOnGroupElementCiphertext(u1, u2, e, v);
		return cipher;
		
	}
	
	/**
	 * Decrypts the given ciphertext using this Cramer-Shoup encryption scheme.
	 * @param ciphertext ciphertext to decrypt. MUST be an instance of CramerShoupCiphertext.
	 * @return Plaintext the decrypted cipher.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given Ciphertext is not instance of CramerShoupCiphertext.
	 */
	@Override
	public Plaintext decrypt(AsymmetricCiphertext ciphertext) throws KeyException{
		/*
			If cipher is not instance of CramerShoupCiphertext, throw IllegalArgumentException.
			If private key is null, then cannot decrypt. Throw exception. 
			Convert u1, u2, e to byte[] using the dlogGroup
			Compute alpha - the result of computing the hash function on the concatenation u1+ u2+ e.
			if u_1^(x1+y1*alpha) * u_2^(x2+y2*alpha) != v throw exception
			Calculate m = e*((u1^z)^-1)   // equal to m = e/u1^z . We don’t have a divide operation in DlogGroup so we calculate it in equivalent way
			m is a groupElement. Use it to create and return msg an instance of GroupElementPlaintext.
			return msg
		 */
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be Cramer Shoup ciphertext.
		if (!(ciphertext instanceof CramerShoupOnGroupElementCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of CramerShoupCiphertext");
		}
		Plaintext plaintext = null;

		CramerShoupOnGroupElementCiphertext cipher = (CramerShoupOnGroupElementCiphertext) ciphertext;
		
		//Converts the u1, u2 and e elements to byte[].
		byte[] u1 = dlogGroup.mapAnyGroupElementToByteArray(cipher.getU1());
		byte[] u2 = dlogGroup.mapAnyGroupElementToByteArray(cipher.getU2());
		byte[] e = dlogGroup.mapAnyGroupElementToByteArray(cipher.getE());
		
		//Calculates the hash(u1 + u2 + e).
		byte[] alpha = calcAlpha(u1, u2, e);

		checkValidity(cipher, alpha);
		
		//Calculates m = e*((u1^z)^ -1). 
		//Instead of calculating (u1^z)^-1, we use the optimization that was calculated in initPrivateKey function and calculate u1^zInv.
		GroupElement U1ExpInvZ = dlogGroup.exponentiate(cipher.getU1(), privateKey.getPrivateExp5());
		GroupElement m = dlogGroup.multiplyGroupElements(cipher.getE(), U1ExpInvZ);
		
		//Creates a plaintext object with the group element and return it.
		plaintext = new GroupElementPlaintext(m);
		
		return plaintext;
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
		return dlogGroup.decodeGroupElementToByteArray(el);
	}

	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 * @deprecated  As of SCAPI-V1-0-2-2 use reconstructCiphertext(AsymmetricCiphertextSendableData data)
	 */
	@Override
	@Deprecated public AsymmetricCiphertext generateCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof CrShOnGroupElSendableData))
				throw new IllegalArgumentException("The input data has to be of type CrShOnGroupElSendableData");
		CrShOnGroupElSendableData data1 = (CrShOnGroupElSendableData)data;
		GroupElement u1 = dlogGroup.generateElement(true, data1.getU1());
		GroupElement u2 = dlogGroup.generateElement(true, data1.getU2());
		GroupElement v = dlogGroup.generateElement(true, data1.getV());
		GroupElement e = dlogGroup.generateElement(true, data1.getE());
	
		return new CramerShoupOnGroupElementCiphertext(u1, u2, v, e);
	}
	
	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 */
	@Override
	public AsymmetricCiphertext reconstructCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof CrShOnGroupElSendableData))
				throw new IllegalArgumentException("The input data has to be of type CrShOnGroupElSendableData");
		CrShOnGroupElSendableData data1 = (CrShOnGroupElSendableData)data;
		GroupElement u1 = dlogGroup.reconstructElement(true, data1.getU1());
		GroupElement u2 = dlogGroup.reconstructElement(true, data1.getU2());
		GroupElement v = dlogGroup.reconstructElement(true, data1.getV());
		GroupElement e = dlogGroup.reconstructElement(true, data1.getE());
	
		return new CramerShoupOnGroupElementCiphertext(u1, u2, v, e);
	}
		
	
}
