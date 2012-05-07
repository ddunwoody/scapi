package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.midLayer.signature.Signature;

/**
 * General interface for digital signatures. Each class of this family must implement this interface. <p>
 * 
 * A digital signature is a mathematical scheme for demonstrating the authenticity of a digital message or document. 
 * A valid digital signature gives a recipient reason to believe that the message was created by a known sender, 
 * and that it was not altered in transit.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DigitalSignature {

	
	/**
	 * Sets this digital signature with public key and private key.
	 * @param publicKey
	 * @param privateKey
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey)throws InvalidKeyException;
	
	/**
	 * Sets this digital signature with a public key<p> 
	 * In this case the signature object can be used only for verification.
	 * @param publicKey
	 */
	public void setKey(PublicKey publicKey)throws InvalidKeyException;
	
	/**
	 * Checks if this digital signature object has been previously initialized.<p> 
	 * To initialize the object the setKey function has to be called with corresponding parameters after construction.
	 * 
	 * @return <code>true<code> if the object was initialized;
	 * 		   <code>false</code> otherwise.
	 */
	public boolean isKeySet();
	
	/**
	 * @return the name of this digital signature
	 */
	public String getAlgorithmName();
	
	/**
	 * Signs the given message
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return the signatures from the msg signing
	 * @throws KeyException if PrivateKey is not set 
	 */
	public Signature sign(byte[] msg, int offset, int length) throws KeyException;
	
	/**
	 * Verifies the given signatures.
	 * @param signature to verify
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return true if the signature is valid. false, otherwise.
	 */
	public boolean verify(Signature signature, byte[] msg, int offset, int length);

	/**
	 * Generates public and private keys for this digital signature.
	 * @param keyParams hold the required key parameters
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates public and private keys for this digital signature.
	 * @return KeyPair holding the public and private keys 
	 */
	public KeyPair generateKey();
}
