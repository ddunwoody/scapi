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
 * This class performs the RSA pss signature scheme.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcRSAPss extends RSAPssAbs{

	private RSAPublicKey publicKey;
	private RSAPrivateKey privateKey;				//set to false until setKey is called
	private CipherParameters privateParameters;		//parameters contains the private key and the random
	private CipherParameters publicParameters;		//parameters contains the public key and the random
	private Digest digest;							//the underlying hash to use
	private PSSSigner signer;						//BC signature object
	private SecureRandom random;
	private int saltLen = 20;
	private boolean forSigning = true;
	
	/**
	 * Default constructor. uses SHA1 and SHA1PRNG random number generator algorithm.
	 * @throws FactoriesException
	 * @throws NoSuchAlgorithmException 
	 */
	public BcRSAPss() throws FactoriesException, NoSuchAlgorithmException{
		//call the other constructor with default parameters
		this("SHA-1", "SHA1PRNG");
	}
	
	/**
	 * Constructor that receives hash name and random number generation algorithm to use.
	 * @param hashName underlying hash to use
	 * @param randNumGenAlg random number generation algorithm to use
	 * @throws FactoriesException if there is no hash with the given name
	 * @throws NoSuchAlgorithmException if there is no random number generation algorithm
	 */
	public BcRSAPss(String hashName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		//creates BC digest with the given name
		digest = BCFactory.getInstance().getDigest(hashName);
		
		//create random with the given algorithm
		this.random = SecureRandom.getInstance(randNumGenAlg);
	}
	
	/**
	 * Constructor that receives hash to use.
	 * @param hash underlying hash to use
	 * @throws FactoriesException if there is no hash with the given name
	 */
	public BcRSAPss(CryptographicHash hash) throws FactoriesException {
		//create SecureRandom object and call the pther constructor
		this(hash, new SecureRandom());
	}
	
	/**
	 * Constructor that receives hash and secure random to use.
	 * @param hash underlying hash to use
	 * @param random secure random to use
	 * @throws FactoriesException if there is no hash with the given name
	 */
	public BcRSAPss(CryptographicHash hash, SecureRandom random) throws FactoriesException{
		//creates BC digest with the given name
		digest = BCFactory.getInstance().getDigest(hash.getAlgorithmName());
		
		//create random with the given algorithm
		this.random = random;
	}
	
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey)
			throws InvalidKeyException {
		//key should be RSA keys
		if(!(publicKey instanceof RSAPublicKey)){
			throw new IllegalArgumentException("keys should be instances of RSA keys");
		}
		if(privateKey!= null && !(privateKey instanceof RSAPrivateKey)){
				throw new IllegalArgumentException("keys should be instances of RSA keys");
		}
		//set the parameters
		this.publicKey = (RSAPublicKey) publicKey;
		publicParameters = BCParametersTranslator.getInstance().translateParameter(this.publicKey, random);
				
		//translate the keys and random to BC parameters
		if (privateKey != null){
			this.privateKey = (RSAPrivateKey) privateKey;
			privateParameters = BCParametersTranslator.getInstance().translateParameter(this.privateKey, random);
		}
		
		
		RSABlindedEngine rsa = new RSABlindedEngine();
		signer = new PSSSigner(rsa, digest, saltLen);
		signer.init(forSigning, privateParameters);
		
		isKeySet = true;
		
	}

	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		//call the other setKey function with null private key
		setKey(publicKey, null);
		
	}

	

	/**
	 * Signs the given message
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return the signature from the msg signing
	 * @throws KeyException if PrivateKey is not set 
	 */
	@Override
	public Signature sign(byte[] msg, int offset, int length) throws KeyException {
		//if there is no private key can not decrypt, throw exception
		if (privateKey == null){
			throw new KeyException("in order to sign a message, this object must be initialized with private key");
		}
		
		//if the underlying BC object used to the signing is in verify mode - change it
		if (!forSigning){
			forSigning = true;
			signer.init(forSigning, privateParameters);
		}
		
		//update the msg in the digest
		signer.update(msg, offset, length);
		byte[] signature = null;
		
		//generate the signature
		try {
			signature = signer.generateSignature();
		} catch (DataLengthException e) {
			throw new ScapiRuntimeException(e.getMessage());
		} catch (CryptoException e) {
			throw new ScapiRuntimeException(e.getMessage());
		}
		return new RSASignature(signature);
	}

	/**
	 * Verifies the given signatures.
	 * @param signature to verify
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return true if the signature is valid. false, otherwise.
	 */
	@Override
	public boolean verify(Signature signature, byte[] msg, int offset, int length) {
		
		if (!(signature instanceof RSASignature)){
			throw new IllegalArgumentException("Signature must be instance of RSASignature");
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
