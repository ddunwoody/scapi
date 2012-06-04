package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import edu.biu.scapi.midLayer.signature.RSASignature;
import edu.biu.scapi.midLayer.signature.Signature;

/**
 * This class is a wrapper for the RSA pss signature scheme of crypto++.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CryptoPPRSAPss extends RSAPssAbs{

	private long signer = 0;
	private long verifier = 0;

	// JNI native functions. The functions of this class call the necessary native function which perform the signature scheme
	private native long createRSASigner();
	private native long createRSAVerifier();
	private native void initRSAVerifier(long verifier, byte[] modulus, byte[] exponent);
	private native void initRSACrtSigner(long signer, byte[] modulus, byte[] exponent, byte[] d, byte[] p, byte[] q, byte[] dp, byte[]dq, byte[] crt);
	private native void initRSASigner(long signer, byte[] modulus, byte[] exponent, byte[] d);
	
	private native byte[] doSign(long signer, byte[] msg, int length);
	private native boolean doVerify(long verifier, byte[] signature, byte[] msg, int msgLen);
	
	
	/**
	 * Default constructor. uses SecureRandom object.
	 */
	public CryptoPPRSAPss() throws NoSuchAlgorithmException{
		//call the other constructor with default parameter
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that receives random number generation algorithm to use.
	 * @param randNumGenAlg random number generation algorithm to use
	 * @throws NoSuchAlgorithmException if there is no random number generation algorithm
	 */
	public CryptoPPRSAPss(String randNumGenAlg) throws NoSuchAlgorithmException {
		//call the other constructor with SecureRandom object
		this(SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Constructor that receives the secure random object to use.
	 * @param random secure random to use
	 */
	public CryptoPPRSAPss(SecureRandom random) {
		this.random = random;
		
		//create the signer and verifier that operates the sign and verify algorithms.
		this.signer = createRSASigner();
		this.verifier = createRSAVerifier();
		
	}
	
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey)
			throws InvalidKeyException {
		if (!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)) {
			throw new InvalidKeyException("Key type doesn't match the RSA signature scheme type");
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
			
			//initializes the native signer
			initRSACrtSigner(signer, modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray(), 
					p.toByteArray(), q.toByteArray(), dp.toByteArray(), dq.toByteArray(), crt.toByteArray());
			
		//if private key is key with N, e, d
		} else {
			
			//init the native signer with the RSA parameters - n, e, d
			initRSASigner(signer, modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray());
		}
		
		//init the native verifier with the RSA parameters - n, e
		initRSAVerifier(verifier, modN.toByteArray(), pubExponent.toByteArray());
		
		isKeySet = true;
		
	}

	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		if(!(publicKey instanceof RSAPublicKey)){
			throw new InvalidKeyException("Key type doesn't match the RSA encryption scheme type");
		}
	
		RSAPublicKey pub = (RSAPublicKey) publicKey;
		BigInteger pubExponent = pub.getPublicExponent();
		BigInteger modN = pub.getModulus();
		
		//init the native verifier with the RSA parameters - n, e
		initRSAVerifier(verifier, modN.toByteArray(), pubExponent.toByteArray());
		isKeySet = true;
		
	}

	/**
	 * Signs the given message using the native signer object
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return the signature from the msg signing
	 * @throws KeyException if PrivateKey is not set 
	 */
	@Override
	public Signature sign(byte[] msg, int offset, int length)
			throws KeyException {
		//if there is no private key can not sign, throw exception
		if (signer == 0){
			throw new KeyException("in order to sign a message, this object must be initialized with private key");
		}
		
		// the native function that perform the sign needs the message to begin at offset 0.
		// so, if the given offset is not 0 copy the msg to a new array. 
		byte[] newMsg = msg;
		if (offset > 0){
			newMsg = new byte[msg.length];
			System.arraycopy(msg, offset, newMsg, 0, length);
		}
		
		//call native function that operates sign
		byte[] signature = doSign(signer, newMsg, length);
		
		return new RSASignature(signature);
	}

	/**
	 * Verifies the given signature using the native verifier object.
	 * @param signature to verify
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return true if the signature is valid. false, otherwise.
	 */
	@Override
	public boolean verify(Signature signature, byte[] msg, int offset,
			int length) {
		if (!(signature instanceof RSASignature)){
			throw new IllegalArgumentException("Signature must be instance of RSASignature");
		}
		
		//get the signature bytes
		byte[] sigBytes = ((RSASignature) signature).getSignatureBytes();
		
		// the native function that perform the sign needs the message to begin at offset 0.
		// so, if the given offset is not 0 copy the msg to a new array. 
		byte[] newMsg = msg;
		if (offset > 0){
			newMsg = new byte[msg.length];
			System.arraycopy(msg, offset, newMsg, 0, length);
		}
		
		//call native function that operates verification
		return doVerify(verifier, sigBytes, newMsg, length);
		
	}
	
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }

}
