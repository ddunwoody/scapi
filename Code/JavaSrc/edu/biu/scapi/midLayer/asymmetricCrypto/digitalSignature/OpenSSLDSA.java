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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DSAPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DSAPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDSAPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDSAPublicKey;
import edu.biu.scapi.midLayer.signature.OpenSSLDSASignature;
import edu.biu.scapi.midLayer.signature.Signature;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.DlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.ZpElement;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;
import edu.biu.scapi.primitives.dlog.openSSL.OpenSSLDlogZpSafePrime;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This class implements the DSA signature scheme using OpenSSL library.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OpenSSLDSA implements DSABasedSignature{

	private long dsa;						// Pointer to the native dsa object.
	private DlogGroup dlog;					// DlogGroup to use in this dsa scheme.
	private DSAPublicKey publicKey;
	private boolean isKeySet;				//Sets to false until setKey is called
	private boolean isPrivateKeySet;		//Sets to false until private key will be set. Indicated if the fign function can be called.
	
	//Native functions that use OpenSSL library.
	//Creates the native dsa object and set the p, q, g parameters.
	private native long createDSA(byte[] p, byte[] q, byte[] g);
	//Sets the public and private keys.
	private native void setKeys(long dsa, byte[] publicKey, byte[] privateKey);
	//Sets the public key.
	private native void setPublicKey(long dsa, byte[] publicKey);
	//Signs the given message.
	private native byte[] sign(long dsa, byte[] msg, int offset, int length);
	//Verifies that the given signature is indeed the dignature of the given message.
	private native boolean verify(long dsa, byte[] signature, byte[] msg, int offset, int length);
	//Generates keys to this dsa scheme.
	private native byte[][] generateKey(long dsa);
	//Delete the native dsa object.
	private native void deleteDSA(long dsa);
	
	/**
	 * Default constructor. uses default implementations of DlogGroup.
	 */
	public OpenSSLDSA(){
		//Call the other constructor with default Dlog value.
		this(new OpenSSLDlogZpSafePrime());	
	}
	
	/**
	 * Constructor that receives dlog name to use.
	 * @param dlogName underlying dlogGroup to use.
	 * @throws FactoriesException if there is no dlog with the given name.
	 */
	public OpenSSLDSA(String dlogName) throws FactoriesException{
		//Creates a dlog and calls the other constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogName));
	}
	
	/**
	 * Constructor that receives a dlog to use.
	 * @param dlog underlying DlogGroup to use.
	 */
	public OpenSSLDSA(DlogGroup dlog){
		if (!(dlog instanceof DlogZpSafePrime)){
			throw new IllegalArgumentException("DSA implementation using OpenSSL library supports Zp group only");
		}
		//Sets the parameters.
		this.dlog = dlog; 
		
		//Creates the native dsa object using the group parameters.
		ZpGroupParams params = (ZpGroupParams) dlog.getGroupParams();
		dsa = createDSA(params.getP().toByteArray(), params.getQ().toByteArray(), params.getXg().toByteArray());
	}
	
	/**
	 * Sets this DSA with public key and private key.
	 * @param publicKey should be an instance of DSAPublicKey.
	 * @param privateKey should be an instance of DSAPrivateKey.
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
		
		//Sets the keys. In case there is a private key set both keys.
		if (privateKey != null){
			
			setKeys(dsa, ((ZpElement)((DSAPublicKey)publicKey).getY()).getElementValue().toByteArray(), 
						 ((DSAPrivateKey) privateKey).getX().toByteArray());
			isPrivateKeySet = true;
		
		//In case there is no private key, set only the public key.	
		} else{
			setPublicKey(dsa, ((ZpElement) ((DSAPublicKey)publicKey).getY()).getElementValue().toByteArray());
		}
		this.publicKey = (DSAPublicKey) publicKey;
		
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
	 * Returns the PublicKey of this DSA signature scheme.
	 * This function should not be use to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the DSAPublicKey
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
		//If there is no private key can not sign, throws exception.
		if (!isPrivateKeySet){
			throw new KeyException("in order to sign a message, this object must be initialized with private key");
		}
		
		// Check that the offset and length are correct.
		if ((offset > msg.length) || (offset+length > msg.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		//Sign the message.
		byte [] signature = sign(dsa, msg, offset, length);
		
		//In OpenSSL implementation the output of the signing is one byte array containing both r and s.
		//This is different than SCAPI implementation for DSA signature, so there is another Signature class (unique for OpenSSL) that holds this result.
		return new OpenSSLDSASignature(signature);
	}


	/**
	 * Verifies the given signatures.
	 * @param signature to verify. Should be an instance of OpenSSLDSASignature.
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
		
		//If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		
		if (!(signature instanceof OpenSSLDSASignature)){
			throw new IllegalArgumentException("Signature must be instance of OpenSSLDSASignature");
		}
		
		// Check that the offset and length are correct.
		if ((offset > msg.length) || (offset+length > msg.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		//Verify the signature.
		return verify(dsa, ((OpenSSLDSASignature)signature).getSignature(), msg, offset, length);
	
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
		//Call the native generateKey function.
		byte[][] keys = generateKey(dsa);
		
		//Create DSA keys from the output.
		ScDSAPublicKey publicKey = new ScDSAPublicKey(dlog.generateElement(false, new BigInteger(keys[0])));
		ScDSAPrivateKey privateKey = new ScDSAPrivateKey(new BigInteger(keys[1]));
		
		//Creates a KeyPair with the created keys.
		return new KeyPair(publicKey, privateKey);
	}
	
	/**
	 * Deletes the related DSA object.
	 */
	protected void finalize() throws Throwable {

		// Delete from the dll the dynamic allocation of the DSA object.
		deleteDSA(dsa);

	}	
	
	//Loads the OpenSSL library.
	static {
		System.loadLibrary("OpenSSLJavaInterface");
	}

}
