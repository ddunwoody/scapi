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

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.signers.PSSSigner;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.ScapiRuntimeException;
import edu.biu.scapi.midLayer.signature.RSASignature;
import edu.biu.scapi.midLayer.signature.Signature;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.tools.Factories.BCFactory;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/**
 * This class implements the RSA PSS signature scheme, using BC RSAPss implementation.
 * The RSA PSS (Probabilistic Signature Scheme) is a provably secure way of creating signatures with RSA.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcRSAPss extends RSAPssAbs {

	private CipherParameters privateParameters;		//parameters that contain the private key and the random
	private CipherParameters publicParameters;		//parameters that contain the public key and the random
	private Digest digest;							//the underlying hash to use
	private PSSSigner signer;						//BC signature object
	private SecureRandom random;
	private boolean forSigning;
	
	/**
	 * Default constructor. uses default implementations of CryptographicHash and SecureRandom.
	 */
	public BcRSAPss() {
		try {
			createBCSigner("SHA-1", new SecureRandom());
		} catch (FactoriesException e) {
			// Shouldn't occur since SHA1 is a valid hash name.
			e.printStackTrace();
		}
	}
	
	/**
	 * Constructor that receives hash name to use.
	 * @param hashName underlying hash to use.
	 * @throws FactoriesException if there is no hash with the given name.
	 */
	public BcRSAPss(String hashName) throws FactoriesException{
		//Creates SecureRandom object and calls the general constructor.
		this (hashName, new SecureRandom());
	}
	
	/**
	 * Constructor that receives hash name and random number generation algorithm to use.
	 * @param hashName underlying hash to use.
	 * @param randNumGenAlg random number generation algorithm to use.
	 * @throws FactoriesException if there is no hash with the given name.
	 * @throws NoSuchAlgorithmException if there is no random number generation algorithm.
	 */
	public BcRSAPss(String hashName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		//Creates SecureRandom object and calls the general constructor.
		this (hashName, SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Constructor that receives hash to use. Uses default implementation of SecureRandom.
	 * @param hash underlying hash to use.
	 * @throws FactoriesException if there is no hash with the given name in BC hash functions.
	 */
	public BcRSAPss(CryptographicHash hash) throws FactoriesException {
		//Creates SecureRandom object and calls the general constructor
		this(hash.getAlgorithmName(), new SecureRandom());
	}
	
	/**
	 * Constructor that receives hash and secure random to use.
	 * @param hash underlying hash to use.
	 * @param random secure random to use.
	 * @throws FactoriesException if there is no hash with the given name.
	 */
	public BcRSAPss(CryptographicHash hash, SecureRandom random) throws FactoriesException{
		//Calls the general constructor with hash name and secure random object.
		this(hash.getAlgorithmName(), random);
	}
	
	/**
	 * Constructor that receives hash name and secure random object to use.
	 * @param hashName underlying hash to use.
	 * @param random secure random to use.
	 * @throws FactoriesException if there is no hash with the given name in BC hash functions.
	 */
	public BcRSAPss(String hashName, SecureRandom random) throws FactoriesException{
		createBCSigner(hashName, random);
	}
	
	private void createBCSigner(String hashName, SecureRandom random) throws FactoriesException{
		//Creates BC digest with the given name.
		digest = BCFactory.getInstance().getDigest(hashName);
		
		this.random = random;
		
		RSABlindedEngine rsa = new RSABlindedEngine();
		signer = new PSSSigner(rsa, digest, digest.getDigestSize());
	}
	
	/**
	 * Sets this RSA PSS scheme with public key and private key.
	 * @param publicKey should be an instance of RSAPublicKey.
	 * @param privateKey hould be an instance of RSAPrivateKey.
	 * @throws InvalidKeyException if the given keys are not instances of RSA keys.
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		//Keys should be RSA keys.
		if(!(publicKey instanceof RSAPublicKey)){
			throw new InvalidKeyException("keys should be instances of RSA keys");
		}
		if((privateKey!= null) && !(privateKey instanceof RSAPrivateKey)){
				throw new InvalidKeyException("keys should be instances of RSA keys");
		}
		//Sets the parameters.
		this.publicKey = (RSAPublicKey) publicKey;
		publicParameters = BCParametersTranslator.getInstance().translateParameter(this.publicKey, random);
				
		//translate the keys and random to BC parameters
		if (privateKey != null){
			privateParameters = BCParametersTranslator.getInstance().translateParameter(privateKey, random);
		}
		
		signer.init(forSigning, publicParameters);
		
		isKeySet = true;
		
	}

	/**
	 * Sets this RSA PSS with a public key.<p> 
	 * In this case the signature object can be used only for verification.
	 * @param publicKey should be an instance of RSAPublicKey.
	 * @throws InvalidKeyException if the given key is not an instance of RSAPublicKey.
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		//Calls the other setKey function with null private key
		setKey(publicKey, null);		
	}

	/**
	 * Signs the given message.
	 * @param msg the byte array to sign.
	 * @param offset the place in the msg to take the bytes from.
	 * @param length the length of the msg.
	 * @return the signature from the msg signing.
	 * @throws KeyException if PrivateKey is not set.
	 * @throws ArrayIndexOutOfBoundsException if the given offset and length are wrong for the given message.
	 * @throws ScapiRuntimeException in case that BC throws an exception of type DataLengthException or CryptoException.
	 */
	@Override
	public Signature sign(byte[] msg, int offset, int length) throws KeyException {
		//If there is no private key can not sign, throws exception.
		if (privateParameters == null){
			throw new KeyException("in order to sign a message, this object must be initialized with private key");
		}
		
		// Checks that the offset and length are correct.
		if ((offset > msg.length) || (offset+length > msg.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		//If the underlying BC object used to the signing is in verify mode - changes it.
		if (!forSigning){
			forSigning = true;
			signer.init(forSigning, privateParameters);
		}
		
		//Updates the msg in the digest.
		signer.update(msg, offset, length);
		byte[] signature = null;
		
		//Generates the signature.
		try {
			signature = signer.generateSignature();
			
		//We wrap this exceptions instead of throwing them because we can't declare them in the interface.
		} catch (DataLengthException e) {
			throw new ScapiRuntimeException(e.getMessage());
		} catch (CryptoException e) {
			throw new ScapiRuntimeException(e.getMessage());
		}
		return new RSASignature(signature);
	}

	/**
	 * Verifies the given signatures.
	 * @param signature to verify. Should be an instance of RSA signature.
	 * @param msg the byte array to verify the signature with.
	 * @param offset the place in the msg to take the bytes from.
	 * @param length the length of the msg.
	 * @return true if the signature is valid. false, otherwise.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Signature is not an instance of RSA signature.
	 * @throws ArrayIndexOutOfBoundsException if the given offset and length are wrong for the given message.
	 */
	@Override
	public boolean verify(Signature signature, byte[] msg, int offset, int length) {
		
		//If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
				
		if (!(signature instanceof RSASignature)){
			throw new IllegalArgumentException("Signature must be instance of RSASignature");
		}
		
		// Checks that the offset and length are correct.
		if ((offset > msg.length) || (offset+length > msg.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		byte[] sigBytes = ((RSASignature) signature).getSignatureBytes();
		
		//if the underlying BC object used to the verification is in signing mode - change it
		if (forSigning){
			forSigning = false;
			signer.init(forSigning, publicParameters);
		}
			
		//update the msg in the digest
		signer.update(msg, offset, length);
		//verify the signature
		return signer.verifySignature(sigBytes);
		
	}

	

}
