/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import edu.biu.scapi.midLayer.ciphertext.BasicAsymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CryptoPPRSAOaep extends RSAOaepAbs {
	
	private long encryptor;
	private long decryptor;
	
	private boolean isKeySet;

	private native long createRSAEncryptor();
	private native long createRSADecryptor();
	private native void initRSAEncryptor(long encryptor, byte[] modulus, byte[] exponent);
	private native void initRSADecryptor(long decryptor, byte[] modulus, byte[] exponent, byte[] d);
	private native void initRSACrtDecryptor(long decryptor, byte[] modulus, byte[] exponent, byte[] d, byte[] p, byte[] q, byte[] dp, byte[]dq, byte[] crt);
	
	private native byte[] getRSAModulus(long encryptor);
	private native byte[] getPubExponent(long encryptor);
	
	private native byte[] doEncrypt(long encryptor, byte[] plaintext);
	private native byte[] doDecrypt(long decryptor, byte[] ciphertext);
	
	public CryptoPPRSAOaep(){
		this(new SecureRandom());
	}
	
	public CryptoPPRSAOaep(SecureRandom secureRandom){
		this.random = secureRandom;
		this.encryptor = createRSAEncryptor();
		this.decryptor = createRSADecryptor();
	}
		
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#setKey(java.security.PublicKey, java.security.PrivateKey)
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		
		if (!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)) {
			throw new InvalidKeyException("Key type doesn't match the RSA encryption scheme type");
		}
			
		/* gets the values of modulus (N), pubExponent (e), privExponent (d)*/
		BigInteger pubExponent = ((RSAPublicKey) publicKey).getPublicExponent();
		BigInteger privExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
		BigInteger modN = ((RSAKey) publicKey).getModulus();
		
		//if private key is CRT private key
		if (privateKey instanceof RSAPrivateCrtKey)
		{
			//gets all the crt parameters
			RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
			BigInteger p = key.getPrimeP();
			BigInteger q = key.getPrimeQ();
			BigInteger dp = key.getPrimeExponentP();
			BigInteger dq = key.getPrimeExponentQ();
			BigInteger crt = key.getCrtCoefficient();
			
			//initializes the native object
			initRSACrtDecryptor(decryptor, modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray(), 
					p.toByteArray(), q.toByteArray(), dp.toByteArray(), dq.toByteArray(), crt.toByteArray());
			
		//if private key is key with N, e, d
		} else {
			
			//init the native object with the RSA parameters - n, e, d
			initRSADecryptor(decryptor, modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray());
		}
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#setKey(java.security.PublicKey)
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		if(!(publicKey instanceof RSAPublicKey)){
			throw new InvalidKeyException("Key type doesn't match the RSA encryption scheme type");
		}
	
		RSAPublicKey pub = (RSAPublicKey) publicKey;
		BigInteger pubExponent = pub.getPublicExponent();
		BigInteger modN = pub.getModulus();
		
		initRSAEncryptor(encryptor, modN.toByteArray(), pubExponent.toByteArray());
		isKeySet = true;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#encrypt(edu.biu.scapi.midLayer.plaintext.Plaintext)
	 */
	@Override
	public Ciphertext encrypt(Plaintext plainText) {
		
		byte[] ciphertext = doEncrypt(encryptor, ((BasicPlaintext)plainText).getText());
		//return a ciphertext with the encrypted plaintext
		return new BasicAsymCiphertext(ciphertext);
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#decrypt(edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 */
	@Override
	public Plaintext decrypt(Ciphertext cipher) throws KeyException {
		
		byte[] plaintext =  doDecrypt(decryptor, ((BasicAsymCiphertext)cipher).getBytes());
		return new BasicPlaintext(plaintext);
	}
}
