/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
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
import edu.biu.scapi.securityLevel.ACMA;
import edu.biu.scapi.securityLevel.UnlimitedTimes;

/**
 * This class implements the RSA PSS signature scheme, using Crypto++ RSAPss implementation.
 * The RSA PSS (Probabilistic Signature Scheme) is a provably secure way of creating signatures with RSA.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CryptoPPRSAPss extends RSAPssAbs implements UnlimitedTimes, ACMA{

	private long signer;		//Pointer to the native Crypto++ signer object.
	private long verifier;		//Pointer to the native Crypto++ verifier object.
	private boolean isPrivateKeySet;
	
	// JNI native functions. The functions of this class call the necessary native functions to perform the signature operations.
	private native long createRSASigner();
	private native long createRSAVerifier();
	private native void initRSAVerifier(long verifier, byte[] modulus, byte[] exponent);
	private native void initRSACrtSigner(long signer, byte[] modulus, byte[] exponent, byte[] d, byte[] p, byte[] q, byte[] dp, byte[]dq, byte[] crt);
	private native void initRSASigner(long signer, byte[] modulus, byte[] exponent, byte[] d);
	
	private native byte[] doSign(long signer, byte[] msg, int length);
	private native boolean doVerify(long verifier, byte[] signature, byte[] msg, int msgLen);
	
	
	/**
	 * Default constructor. uses default implementation of SecureRandom.
	 */
	public CryptoPPRSAPss(){
		//Calls the other constructor with default parameter.
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that receives random number generation algorithm to use.
	 * @param randNumGenAlg random number generation algorithm to use
	 * @throws NoSuchAlgorithmException if there is no random number generation algorithm
	 */
	public CryptoPPRSAPss(String randNumGenAlg) throws NoSuchAlgorithmException {
		//Calls the other constructor with SecureRandom object.
		this(SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Constructor that receives the secure random object to use.
	 * @param random secure random to use
	 */
	public CryptoPPRSAPss(SecureRandom random) {
		this.random = random;
		
		//Creates the signer and verifier objects that perform the sign and verify operations.
		this.signer = createRSASigner();
		this.verifier = createRSAVerifier();
		
	}
	
	/**
	 * Sets this RSA PSS scheme with public key and private key.
	 * @param publicKey should be an instance of RSAPublicKey.
	 * @param privateKey hould be an instance of RSAPrivateKey.
	 * @throws InvalidKeyException if the given keys are not instances of RSA keys.
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey)
			throws InvalidKeyException {
		if (!(publicKey instanceof RSAPublicKey)) {
			throw new InvalidKeyException("Key type doesn't match the RSA signature scheme type");
		}
		
		if ((privateKey!=null) && !(privateKey instanceof RSAPrivateKey)){
			throw new InvalidKeyException("Key type doesn't match the RSA signature scheme type");
		}
			
		//Notice! We set the public key twice - in the PublicKey member and in the native verifier object.
		//This can lead to many synchronization problems, so we need to be very careful not to change just one of them.
		this.publicKey = (RSAPublicKey) publicKey;
		
		/* Gets the values of modulus (N), pubExponent (e), privExponent (d)*/
		BigInteger pubExponent = ((RSAPublicKey) publicKey).getPublicExponent();
		BigInteger modN = ((RSAKey) publicKey).getModulus();
		
		//Initializes the native verifier with the RSA parameters - n, e.
		initRSAVerifier(verifier, modN.toByteArray(), pubExponent.toByteArray());
		
		if (privateKey != null){
			
			BigInteger privExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
			//If private key is CRT private key.
			if (privateKey instanceof RSAPrivateCrtKey)
			{
				//Gets all the crt parameters
				RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
				BigInteger p = key.getPrimeP();
				BigInteger q = key.getPrimeQ();
				BigInteger dp = key.getPrimeExponentP();
				BigInteger dq = key.getPrimeExponentQ();
				BigInteger crt = key.getCrtCoefficient();
				
				//Initializes the native signer.
				initRSACrtSigner(signer, modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray(), 
						p.toByteArray(), q.toByteArray(), dp.toByteArray(), dq.toByteArray(), crt.toByteArray());
				
			//If private key is key with N, e, d.
			} else {
				
				//Initializes the native signer with the RSA parameters - n, e, d.
				initRSASigner(signer, modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray());
			}
			isPrivateKeySet = true;
		}
		
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
		setKey(publicKey, null);
		
	}

	/**
	 * Signs the given message using the native signer object.
	 * @param msg the byte array to verify the signature with.
	 * @param offset the place in the msg to take the bytes from.
	 * @param length the length of the msg.
	 * @return the signature from the msg signing.
	 * @throws KeyException if PrivateKey is not set.
	 * @throws ArrayIndexOutOfBoundsException if the given offset and length are wrong for the given message.
	 */
	@Override
	public Signature sign(byte[] msg, int offset, int length)
			throws KeyException {
		//If there is no private key can not sign, throws exception.
		if (!isPrivateKeySet){
			throw new KeyException("in order to sign a message, this object must be initialized with private key");
		}
		
		// Checks that the offset and length are correct.
		if ((offset > msg.length) || (offset+length > msg.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		
		// The native function that perform the sign needs the message to begin at offset 0.
		// If the given offset is not 0 copy the msg to a new array. 
		byte[] newMsg = msg;
		if (offset > 0){
			newMsg = new byte[msg.length];
			System.arraycopy(msg, offset, newMsg, 0, length);
		}
		
		//Calls native function that performs the signing.
		byte[] signature = doSign(signer, newMsg, length);
		
		return new RSASignature(signature);
	}

	/**
	 * Verifies the given signature using the native verifier object.
	 * @param signature to verify should be an instance of RSASignature.
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return true if the signature is valid. false, otherwise.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Signature is not an instance of RSASignature.
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
		
		//Gets the signature bytes
		byte[] sigBytes = ((RSASignature) signature).getSignatureBytes();
		
		// The native function that perform the sign needs the message to begin at offset 0.
		// If the given offset is not 0 copy the msg to a new array. 
		byte[] newMsg = msg;
		if (offset > 0){
			newMsg = new byte[msg.length];
			System.arraycopy(msg, offset, newMsg, 0, length);
		}
		
		//Calls native function that perform the verification.
		return doVerify(verifier, sigBytes, newMsg, length);
		
	}
	
	//Loads the Crypto++ library.
	static {
	      System.loadLibrary("CryptoPPJavaInterface");
	}

}
