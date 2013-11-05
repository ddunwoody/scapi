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

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPrivateKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnByteArrayCiphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnByteArrayCiphertext.ElGamalOnByteArraySendableData;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * This class performs the El Gamal encryption scheme that perform the encryption on a ByteArray.
 * The general encryption of a message usually uses this type of encryption. <p>
 * 
 * By definition, this encryption scheme is CPA-secure and Indistinguishable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScElGamalOnByteArray extends ElGamalAbs{

	private KeyDerivationFunction kdf; 	// The underlying KDF to use in the encryption.
	
	/**
	 * Default constructor. Uses the default implementations of DlogGroup and SecureRandom.
	 */
	public ScElGamalOnByteArray() {
		super();
		//Creates a default implementation of KDF.
		setKdf(new HKDF(new BcHMAC()));
	}

	private void setKdf(KeyDerivationFunction kdf){
		this.kdf = kdf;
	}
	
	/**
	 * Constructor that gets a DlogGroup and sets it to the underlying group.
	 * It lets SCAPI choose and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 */
	public ScElGamalOnByteArray(DlogGroup dlogGroup, KeyDerivationFunction kdf) throws SecurityLevelException {
		super(dlogGroup, new SecureRandom());
		setKdf(kdf);
	}
	/**
	 * Constructor that gets a DlogGroup and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @param random source of randomness.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 */
	public ScElGamalOnByteArray(DlogGroup dlogGroup, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException {
		super(dlogGroup, random);
		//Sets the given KDF.
		setKdf(kdf);
	}
	
	/**
	 * Constructor that gets a DlogGroup name to create and sets it to the underlying group.
	 * Uses default implementation of SecureRandom.
	 * @param dlogName must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed. 
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level. 
	 */
	public ScElGamalOnByteArray(String dlogName, String kdfName) throws FactoriesException, SecurityLevelException{
		super(dlogName);
		//Sets the given KDF.
		setKdf(KdfFactory.getInstance().getObject(kdfName));
	}
	
	
	/**
	 * Constructor that gets a DlogGroup name to create and random number generator to use.
	 * @param dlogName must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws NoSuchAlgorithmException if the given random number generator is not supported.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 */
	public ScElGamalOnByteArray(String dlogName, String kdfName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException, SecurityLevelException{
		super(dlogName, randNumGenAlg);
		//Sets the given KDF.
		setKdf(KdfFactory.getInstance().getObject(kdfName));
	}
	

	/**
	 * Sets the private key.
	 * @param privateKey.
	 */
	protected void initPrivateKey(PrivateKey privateKey){
		//Sets the given PrivateKey.
		this.privateKey = (ElGamalPrivateKey) privateKey;
	}
	
	/**
	 * ElGamalOnByteArray encryption scheme has no limit of the byte array length to generate a plaintext from.
	 * @return false. 
	 */
	public boolean hasMaxByteArrayLengthForPlaintext(){
		return false;
	}
	
	/**
	 * ElGamalOnByteArray encryption can get any plaintext length.
	 * @throws NoMaxException.
	 */
	public int getMaxLengthOfByteArrayForPlaintext(){
		throw new NoMaxException("ElGamalOnByteArray encryption can get any plaintext length");
	}
	
	/**
	 * Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 */
	public Plaintext generatePlaintext(byte[] text){
		
		return new ByteArrayPlaintext(text);
	}
	
	/**
	 * Completes the encryption operation.
	 * @param plaintext contains message to encrypt. MUST be of type ByteArrayPlaintext.
	 * @return Ciphertext of type ElGamalOnByteArrayCiphertext containing the encrypted message.
	 * @throws IllegalArgumentException if the given Plaintext is not an instance of ByteArrayPlaintext.
	 */
	protected AsymmetricCiphertext completeEncryption(GroupElement c1, GroupElement hy, Plaintext plaintext){
		
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of ByteArrayPlaintext");
		}
	
		//Gets the message.
		byte[] msg = ((ByteArrayPlaintext) plaintext).getText();
	
		byte[] hyBytes = dlog.mapAnyGroupElementToByteArray(hy);
		byte[] c2 = kdf.deriveKey(hyBytes, 0, hyBytes.length, msg.length).getEncoded();
		
		//Xores the result from the kdf with the plaintext.
		for(int i=0; i<msg.length; i++){
			c2[i] = (byte) (c2[i] ^ msg[i]);
		}
		
		//Returns an ElGamalOnByteArrayCiphertext with c1, c2.
		return new ElGamalOnByteArrayCiphertext(c1, c2);
	}

	/**
	 * Decrypts the given ciphertext using ElGamal encryption scheme.
	 *
	 * @param cipher MUST be of type ElGamalOnByteArrayCiphertext contains the cipher to decrypt.
	 * @return Plaintext of type ByteArrayPlaintext which containing the decrypted message.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given cipher is not instance of ElGamalOnByteArrayCiphertext.
	 */
	public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException {
		/*  
		 * Pseudo-code:
		 * 	•	Calculate s = ciphertext.getC1() ^ x
		 *	•	Calculate m = KDF(s) XOR ciphertext.getC2() 
		 */
		
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be ElGamal ciphertext.
		if (!(cipher instanceof ElGamalOnByteArrayCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of ElGamalOnByteArrayCiphertext");
		}

		ElGamalOnByteArrayCiphertext ciphertext = (ElGamalOnByteArrayCiphertext) cipher;
		//Calculates s = ciphertext.getC1() ^ x.
		GroupElement s = dlog.exponentiate(ciphertext.getC1(), privateKey.getX());
		byte[] sBytes = dlog.mapAnyGroupElementToByteArray(s);
		byte[] c2 = ciphertext.getC2();
		//Calculates the plaintext element m = KDF(s) ^ c2.
		byte[] m = kdf.deriveKey(sBytes, 0, sBytes.length, c2.length).getEncoded();
		
		//Xores the result from the kdf with the plaintext.
		for(int i=0; i<c2.length; i++){
			m[i] = (byte) (m[i] ^ c2[i]);
		}
		
		//Creates a plaintext object with the element and returns it.
		return new ByteArrayPlaintext(m);
	}

	/**
	 * Generates a byte array from the given plaintext. 
	 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has, 
	 * and therefore he is working on byte array.
	 * @param plaintext to generates byte array from. MUST be an instance of ByteArrayPlaintext.
	 * @return the byte array generated from the given plaintext.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of ByteArrayPlaintext.
	 */
	public byte[] generateBytesFromPlaintext(Plaintext plaintext){
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be an instance of ByteArrayPlaintext");
		}
		
		return ((ByteArrayPlaintext) plaintext).getText();
	}
	
	
	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 * @deprecated As of SCAPI-V1-0-2-2 use reconstructCiphertext(AsymmetricCiphertextSendableData data)
	 */
	@Override
	@Deprecated public AsymmetricCiphertext generateCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof ElGamalOnByteArraySendableData))
				throw new IllegalArgumentException("The input data has to be of type ElGamalOnByteArraySendableData");
		ElGamalOnByteArraySendableData data1 = (ElGamalOnByteArraySendableData)data;
		GroupElement cipher1 = dlog.generateElement(true, data1.getCipher1());
			
		return new ElGamalOnByteArrayCiphertext(cipher1, data1.getCipher2());
	}
	
	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 */
	@Override
	public AsymmetricCiphertext reconstructCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof ElGamalOnByteArraySendableData))
				throw new IllegalArgumentException("The input data has to be of type ElGamalOnByteArraySendableData");
		ElGamalOnByteArraySendableData data1 = (ElGamalOnByteArraySendableData)data;
		GroupElement cipher1 = dlog.reconstructElement(true, data1.getCipher1());
			
		return new ElGamalOnByteArrayCiphertext(cipher1, data1.getCipher2());
	}
}
