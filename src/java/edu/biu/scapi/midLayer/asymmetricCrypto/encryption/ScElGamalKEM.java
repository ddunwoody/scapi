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

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPrivateKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;
import edu.biu.scapi.midLayer.ciphertext.ElGamalKEMCiphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalKEMCiphertext.ElGamalKEMSendableData;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScCTREncRandomIV;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.SymmetricEnc;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.securityLevel.Cpa;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * This class performs the El Gamal KEM encryption scheme.
 * 
 * By definition, this encryption scheme is CPA-secure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScElGamalKEM extends ElGamalAbs{

	private KeyDerivationFunction kdf; 		// The underlying KDF to use in the encryption.
	private SymmetricEnc symEncryptor;		// The underlying Symmetric Encryption to use.
	private int symKeySize;					// key size for the underlying symmetric encryption.
	
	/**
	 * Default constructor. Uses the default implementations of DlogGroup, KDF, SymmetricEncryption and SecureRandom.
	 */
	public ScElGamalKEM(){
		super();
		//Creates a default implementation of KDF and SymmetricEncryption.
		try {
			setMembers(new HKDF(new BcHMAC()), new ScCTREncRandomIV(new BcAES()), 128);
		} catch (SecurityLevelException e) {
			// Should not occur since the created encryption is CPA - secure.
		}
	}

	/**
	 * Sets the given KDF and Symmetric Encryption.
	 * @param kdf
	 * @param encryption MUST be CPA-secure.
	 * @param symKeySize Size of the key to set the given symmetric encryption, in BITS.
	 * @throws SecurityLevelException if encryption is not CPA-secure
	 */
	private void setMembers(KeyDerivationFunction kdf, SymmetricEnc encryption, int symKeySize) throws SecurityLevelException{
		//The underlying symmetric encryption should be CPA-secure.
		if (!(encryption instanceof Cpa)){
			throw new SecurityLevelException("Symmetric encryption should have CPA security level"); 
		}
		symEncryptor = encryption; 
		this.kdf = kdf;
		this.symKeySize = symKeySize;
	}
	
	/**
	 * Constructor that gets a DlogGroup, KDF and symmetric encryption and sets them.
	 * It lets SCAPI choose the source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @param kdf
	 * @param encryption MUST be CPA-secure.
	 * @param symKeySize Size of the key to set the given symmetric encryption, in BITS.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 * @throws SecurityLevelException if the given encryption is not CPA-secure.
	 */
	public ScElGamalKEM(DlogGroup dlogGroup, KeyDerivationFunction kdf, SymmetricEnc encryption, int symKeySize) throws SecurityLevelException {
		super(dlogGroup, new SecureRandom());
		setMembers(kdf, encryption, symKeySize);
	}
	/**
	 * Constructor that gets a DlogGroup, KDF, symmetric encryption and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @param random source of randomness.
	 * @param kdf
	 * @param encryption MUST be CPA-secure.
	 * @param symKeySize Size of the key to set the given symmetric encryption, in BITS.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 * @throws SecurityLevelException if the given encryption is not CPA-secure.
	 */
	public ScElGamalKEM(DlogGroup dlogGroup, KeyDerivationFunction kdf, SymmetricEnc encryption, int symKeySize, SecureRandom random) throws SecurityLevelException {
		super(dlogGroup, random);
		//Sets the given KDF and symmetric encryption.
		setMembers(kdf, encryption, symKeySize);
	}
	
	/**
	 * Constructor that gets a DlogGroup name and kdf name to create and sets them to the underlying members.
	 * The constructor also gets the underlying SymmetricEncryption to use. 
	 * It does not get the name of the encryption since there is no factory for the Symmetric encryption so it cannot be created by name.
	 * Uses default implementation of SecureRandom.
	 * @param dlogName must be DDH secure.
	 * @param kdfName
	 * @param encryption MUST be CPA-secure.
	 * @param symKeySize Size of the key to set the given symmetric encryption, in BITS.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 * @throws SecurityLevelException if the given encryption is not CPA-secure.
	 */
	public ScElGamalKEM(String dlogName, String kdfName, SymmetricEnc encryption, int symKeySize) throws FactoriesException, SecurityLevelException{
		super(dlogName);
		//Sets the given KDF and symmetric encryption.
		setMembers(KdfFactory.getInstance().getObject(kdfName), encryption, symKeySize);
	}
	
	
	/**
	 * Constructor that gets a DlogGroup name, kdf name and random number generator to use.
	 * The constructor also gets the underlying SymmetricEncryption to use. 
	 * It does not get the name of the encryption since there is no factory for the Symmetric encryption so it cannot be created by name.
	 * @param dlogName must be DDH-secure.
	 * @param kdfName
	 * @param encryption MUST be CPA-secure.
	 * @param symKeySize Size of the key to set the given symmetric encryption, in BITS.
	 * @param randNumGenAlg
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws NoSuchAlgorithmException if the given random number generator is not supported.
	 * @throws SecurityLevelException if the given dlog group does not have DDH security level.
	 * @throws SecurityLevelException if the given encryption is not CPA-secure.
	 */
	public ScElGamalKEM(String dlogName, String kdfName, SymmetricEnc encryption, int symKeySize, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException, SecurityLevelException{
		super(dlogName, randNumGenAlg);
		//Sets the given KDF and symmetric encryption.
		setMembers(KdfFactory.getInstance().getObject(kdfName), encryption, symKeySize);
	}
	

	/**
	 * Sets the private key.
	 * @param privateKey to change.
	 */
	protected void initPrivateKey(PrivateKey privateKey){
		//Sets the given PrivateKey.
		this.privateKey = (ElGamalPrivateKey) privateKey;
	}
	
	/**
	 * ElGamalKEM encryption scheme has no limit of the byte array length to generate a plaintext from.
	 * @return false. 
	 */
	public boolean hasMaxByteArrayLengthForPlaintext(){
		return false;
	}
	
	/**
	 * ElGamalKEM encryption can get any plaintext length.
	 * @throws NoMaxException.
	 */
	public int getMaxLengthOfByteArrayForPlaintext(){
		throw new NoMaxException("ElGamalKEM encryption can get any plaintext length");
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
	 * @return Ciphertext of type ElGamalKEMCiphertext containing the encrypted message.
	 * @throws IllegalArgumentException if the given Plaintext is not an instance of ByteArrayPlaintext.
	 */
	protected AsymmetricCiphertext completeEncryption(GroupElement u, GroupElement v, Plaintext plaintext){
		
		/*
		 * Pseudo code:
		 * 		Choose a random r in Zq
		 *      Compute u=g^r and v=h^r
		 *         [The two steps above are done in the abstract class.]
		 *      Compute k = KDF(v) with the number of bits being the key size needed for the CPA-secure symmetric encryption scheme
		 *     	Encrypt m with key k, using the CPA-secure symmetric encryption scheme; denote the resulting ciphertext by w
		 *     	Output the ciphertext c=(u,w)
		 */
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of ByteArrayPlaintext");
		}
	
		//calculate a key for the symmetric encryption.
		byte[] vBytes = dlog.mapAnyGroupElementToByteArray(v);
		byte[] k = kdf.deriveKey(vBytes, 0, vBytes.length, symKeySize/8).getEncoded();
		
		//Sets the computed key.
		try {
			symEncryptor.setKey(new SecretKeySpec(k, ""));
		} catch (InvalidKeyException e) {
			// shouldn't occur since the size is legal.
			e.printStackTrace();
		}
		
		//encrypt the message using the symmetric encryption
		SymmetricCiphertext w = symEncryptor.encrypt(plaintext);
		
		//Returns an ElGamalKEMCiphertext with u and the symmetric ciphertext.
		return new ElGamalKEMCiphertext(u, w);
	}

	/**
	 * Decrypts the given ciphertext using ElGamal encryption scheme.
	 *
	 * @param cipher MUST be of type ElGamalKEMCiphertext contains the cipher to decrypt.
	 * @return Plaintext of type ByteArrayPlaintext which containing the decrypted message.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given cipher is not instance of ElGamalOnByteArrayCiphertext.
	 */
	public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException {
		/*  
		 * Pseudo-code:
		 * 		Compute v = u^x
		 *      Compute k = KDF(v) with the number of bits being the key size needed for the CPA-secure symmetric encryption scheme
		 *      Decrypt w with key k, using the CPA-secure symmetric encryption scheme; denote the resulting by m
		 *      Output m
		 */
		
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be ElGamalKEM ciphertext.
		if (!(cipher instanceof ElGamalKEMCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of ElGamalKEMCiphertext");
		}

		ElGamalKEMCiphertext ciphertext = (ElGamalKEMCiphertext) cipher;
		//Calculates v = u^x.
		GroupElement v = dlog.exponentiate(ciphertext.getU(), privateKey.getX());
		
		//calculate a key for the symmetric encryption.
		byte[] vBytes = dlog.mapAnyGroupElementToByteArray(v);
		byte[] k = kdf.deriveKey(vBytes, 0, vBytes.length, symKeySize/8).getEncoded();
		
		//Sets the symmetric key.
		try {
			symEncryptor.setKey(new SecretKeySpec(k, ""));
		} catch (InvalidKeyException e) {
			// shouldn't occur since the size is legal.
			e.printStackTrace();
		}
		
		//Decrypt and return the message using the symmetric encryption object.
		return symEncryptor.decrypt(ciphertext.getW());
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
		
		return reconstructCiphertext(data);
	}
	
	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 */
	@Override
	public AsymmetricCiphertext reconstructCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof ElGamalKEMSendableData))
				throw new IllegalArgumentException("The input data has to be of type ElGamalKemSendableData");
		ElGamalKEMSendableData data1 = (ElGamalKEMSendableData)data;
		GroupElement u = dlog.reconstructElement(true, data1.getU());
		SymmetricCiphertext w = data1.getW();
		
		return new ElGamalKEMCiphertext(u, w);
	}

}
