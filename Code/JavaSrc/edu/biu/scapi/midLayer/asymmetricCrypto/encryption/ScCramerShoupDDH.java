/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.ScapiRuntimeException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.*;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.*;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCramerShoupDDH implements CramerShoupDDHEnc {
	
	private DlogGroup dlogGroup;
	private CryptographicHash hash;
	private CramerShoupPublicKey publicKey;
	private CramerShoupPrivateKey privateKey;
	private SecureRandom random;
	private BigInteger qMinusOne; 
	private boolean isKeySet = false;
	
	/**
	 * Default constructor. It uses a Dlog group over Zp with p of size 1024 bits, and SHA1.
	 */
	public ScCramerShoupDDH() {
		this(new CryptoPpDlogZpSafePrime("1024"), new CryptoPpSHA1(), new SecureRandom());
	}


	public ScCramerShoupDDH(DlogGroup dlogGroup, CryptographicHash hash){
		this(dlogGroup, hash, new SecureRandom());
	}

	public ScCramerShoupDDH(DlogGroup dlogGroup, CryptographicHash hash, SecureRandom random){
		if(!(dlogGroup instanceof DDH)){
			throw new IllegalArgumentException("The Dlog group has to have DDH security level");
		}
		//Everything is correct, then set the member variables and create object.
		this.dlogGroup = dlogGroup;
		qMinusOne = dlogGroup.getOrder().subtract(BigInteger.ONE);
		this.hash = hash;
		this.random = random;
	}

	public ScCramerShoupDDH(String dlogGroupName, String hashName) throws FactoriesException{
		//Create a dlog group object and a cryptographic hash object with relevant factories, and then use regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogGroupName), CryptographicHashFactory.getInstance().getObject(hashName));
	}
	
	public ScCramerShoupDDH(String dlogGroupName, String hashName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		//Create a dlog group object and a cryptographic hash object with relevant factories.
		//Create a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
		//Then use regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogGroupName), CryptographicHashFactory.getInstance().getObject(hashName), SecureRandom.getInstance(randNumGenAlg));
	}
	
	
	/**
	 * This function sets the Public\Private key
	 * @param publicKey the public key has to be of type <link>CramerShoupPublicKey<link>
	 * @param privateKey the private key has to be of type <link>CramerShoupPrivateKey<link>
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#init(java.security.PublicKey, java.security.PrivateKey, java.security.spec.AlgorithmParameterSpec, java.security.SecureRandom)
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws  InvalidKeyException{
		
		//public key should be Cramer Shoup public key
		if(!(publicKey instanceof ScCramerShoupPublicKey)){
			throw new InvalidKeyException("The public key must be of type CramerShoupPublicKey");
		}
		//Set the public key
		this.publicKey = (ScCramerShoupPublicKey) publicKey;

		//private key should be Cramer Shoup private key	
		if(privateKey == null){
			//If the private key in the argument is null then this instance's private key should be null.  
			this.privateKey = null;
		}else{
			if(!(privateKey instanceof ScCramerShoupPrivateKey)){
				throw new InvalidKeyException("The private key must be of type CramerShoupPrivatKey");
			}
			//Set the private key
			this.privateKey = (ScCramerShoupPrivateKey) privateKey;
		}
		isKeySet = true;
	}

	/**
	 * This function sets only the Public key.
	 * Setting only the public key the user can encrypt messages but can not decrypt messages.
	 * @param publicKey the public key has to be of type <link>CramerShoupPublicKey<link>
	 */
	@Override
	public void setKey(PublicKey publicKey) throws  InvalidKeyException{
		setKey(publicKey, null);
	}



	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateKey(java.security.SecureRandom)
	 * 	Given a Dlog Group (G, q, g) do: 
			Choose two distinct, random generators g1, g2. (how?)
			Choose five random values (x1, x2, y1, y2, z) in Zq.
			Compute c = g_1^(x_1 ) g_2^(x_2 ), d= g_1^(y_1 ) g_2^(y_2 ), h= g_1^z.
			Set the public key part of the key pair to be c, d, h. (Or (G, q, g, c, d, h) ?)
			Set the private key part of the key pair to be x1, x2, y1, y2, z. (Or (G, q, g, x1, x2, y1, y2, z) ?)
			Return the key pair.

	 */
	public KeyPair generateKey() {

		GroupElement generator1 = null;
		GroupElement generator2 = null;
		do {
			//(What source of randomness do we use here?)
			generator1 = dlogGroup.getRandomElement();
			generator2 = dlogGroup.getRandomElement();
		}while(generator1.equals(generator2));
		//Check that the "generators" randomly chosen are actually generators and are distinct:
		
		//Choose five random values (x1, x2, y1, y2, z) in Zq.
		BigInteger x1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger x2 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger y1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger y2 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		BigInteger z = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		
		//Calculate c, d and h:
		GroupElement c = null;
		GroupElement d = null; 
		GroupElement h = null;
		
		try {
			c = dlogGroup.multiplyGroupElements(dlogGroup.exponentiate(generator1,x1), dlogGroup.exponentiate(generator2, x2));
			d = dlogGroup.multiplyGroupElements(dlogGroup.exponentiate(generator1,y1), dlogGroup.exponentiate(generator2, y2));
			h = dlogGroup.exponentiate(generator1, z);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		}
		
		CramerShoupPublicKey publicKey = new ScCramerShoupPublicKey(c, d, h, generator1, generator2);
		
		CramerShoupPrivateKey privateKey = new ScCramerShoupPrivateKey(x1, x2, y2, y2, z);
		
		KeyPair keyPair = new KeyPair(publicKey, privateKey);
		
		return keyPair;
	}
	
	/**
	 * There is no need for parameters to generate an El Gamal key pair. Therefore this operation is not supported.
	 * @throws UnsupportedOperationException
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//No need for parameters to generate an El Gamal key pair. Therefore this operation is not supported
		throw new UnsupportedOperationException();
	}
	
	public boolean isKeySet() {
		return isKeySet;
	}


	@Override
	public String getAlgorithmName() {
		return "CramerShoupp/"+dlogGroup.getGroupType();
	}

	/* (non-Javadoc)
	 * 	If !dlogGroup.convertByteArrayToGroupElement(plaintext.getText()) throw exception.<p>
	 *	Choose a random  r in Zq<p>
	 *	Calculate 	u1 = g1^r<p>
	 *         		u2 = g2^r<p>
	 *         		e = (h^r)*msgEl<p>
	 *	Convert u1, u2, e to byte[] using the dlogGroup<P>
	 *	Compute alpha  - the result of computing the hash function on the concatenation u1+ u2+ e.<>
	 *	Calculate v = c^r * d^(r*alpha)<p>
	 *	Create and return an CramerShoupCiphertext object with u1, u2, e and v.
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#encrypt(edu.biu.scapi.midLayer.plaintext.Plaintext)
	 */
	@Override
	public Ciphertext encrypt(Plaintext plaintext) {
		GroupElement msgElement = dlogGroup.convertByteArrayToGroupElement(((BasicPlaintext)plaintext).getText());
		
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		GroupElement u1 = dlogGroup.exponentiate(publicKey.getGenerator1(), r);
		GroupElement u2 = dlogGroup.exponentiate(publicKey.getGenerator2(), r);
		GroupElement hExpr = dlogGroup.exponentiate(publicKey.getH(), r);
		GroupElement e = dlogGroup.multiplyGroupElements(hExpr, msgElement);
		byte[] u1ToByteArray = dlogGroup.convertGroupElementToByteArray(u1);
		byte[] u2ToByteArray = dlogGroup.convertGroupElementToByteArray(u2);
		byte[] eToByteArray = dlogGroup.convertGroupElementToByteArray(e);
		
		//Concatenate u1, u2 and e into msgToHash
		int lengthOfMsgToHash =  u1ToByteArray.length + u2ToByteArray.length + eToByteArray.length;
		byte[] msgToHash = new byte[lengthOfMsgToHash];
		System.arraycopy(u1ToByteArray, 0, msgToHash, 0, u1ToByteArray.length);
		System.arraycopy(u2ToByteArray, 0, msgToHash, u1ToByteArray.length, u2ToByteArray.length);
		System.arraycopy(eToByteArray, 0, msgToHash, u2ToByteArray.length, eToByteArray.length);
		
		//Calculate the hash of msgToHash
		
		//call the update function in the Hash interface.
		hash.update(msgToHash, 0, msgToHash.length);

		//get the result of hashing the updated input.
		byte[] alpha = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(alpha, 0);
		
		
		//Calculate v = c^r * d^(r*alpha)
		GroupElement cExpr = dlogGroup.exponentiate(publicKey.getC(), r);
		BigInteger q = dlogGroup.getOrder();
		BigInteger rAlphaModQ = (r.multiply(new BigInteger(alpha))).mod(q);
		GroupElement dExpRAlpha = dlogGroup.exponentiate(publicKey.getD(), rAlphaModQ);
		GroupElement v = dlogGroup.multiplyGroupElements(cExpr, dExpRAlpha); 
		
		//Create and return an CramerShoupCiphertext object with u1, u2, e and v.
		CramerShoupCiphertext cipher = new CramerShoupCiphertext(u1, u2, e, v);
		return cipher;
	}
	/*
	If cipher is not instance of CramerShoupCiphertext, throw IllegalArgumentException.
	If private key is null, then cannot decrypt. Throw exception. [TODO decide which exception]
	Convert u1, u2, e to byte[] using the dlogGroup
	Compute alpha - the result of computing the hash function on the concatenation u1+ u2+ e.
	if u_1^(x_1+y_1*alpha) * u_2^(x_2+y_2*alpha) != v throw exception
	Calculate m = e*((u1^z)^-1)   // equal to m = e/u1^z . We don’t have a divide operation in DlogGroup so we calculate it in equivalent way
	m is a groupElement. Use it to create and return msg an instance of ElGamalPlaintext.
	return msg
	 */
	
	/*
	 * 
	 */
	@Override
	public Plaintext decrypt(Ciphertext ciphertext) throws KeyException {
		//if there is no private key, throw exception
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//ciphertext should be ElGamal ciphertext
		if (!(ciphertext instanceof CramerShoupCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of CramerShoupCiphertext");
		}
		Plaintext plaintext = null;

		CramerShoupCiphertext cipher = (CramerShoupCiphertext) ciphertext;
		
		//convert the u1, u2 and e elements to byte[]
		byte[] u1 = dlogGroup.convertGroupElementToByteArray(cipher.getU1());
		byte[] u2 = dlogGroup.convertGroupElementToByteArray(cipher.getU2());
		byte[] e = dlogGroup.convertGroupElementToByteArray(cipher.getE());
		
		//Concatenate u1, u2 and e into msgToHash
		int lengthOfHash =  u1.length + u2.length + e.length;
		byte[] msgToHash = new byte[lengthOfHash];
		System.arraycopy(u1, 0, msgToHash, 0, u1.length);
		System.arraycopy(u2, 0, msgToHash, u1.length, u2.length);
		System.arraycopy(e, 0, msgToHash, u2.length, e.length);
		
		//Calculate the hash(u1 + u2 + e) 
		
		//call the update function in the Hash interface.
		hash.update(msgToHash, 0, msgToHash.length);

		//get the result of hashing the updated input.
		byte[] alpha = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(alpha, 0);

		//calculate u_1^(x_1+y_1*alpha)
		BigInteger exponent1 = privateKey.getPrivateExp1().add((privateKey.getPrivateExp3().multiply(new BigInteger(alpha))));
		GroupElement t1 = dlogGroup.exponentiate(cipher.getU1(),exponent1);
		//calculate u_2^(x_2+y_2*alpha)
		BigInteger exponent2 = privateKey.getPrivateExp2().add((privateKey.getPrivateExp4().multiply(new BigInteger(alpha))));
		GroupElement t2 = dlogGroup.exponentiate(cipher.getU1(),exponent2);

		//verify that their multiplication is equal to v. If not, throw exception
		GroupElement mult = dlogGroup.multiplyGroupElements(t1, t2);
		if (!mult.equals(cipher.getV())){
			throw new ScapiRuntimeException("Error! Cannot proceed with decryption"); //TODO Need to decide if this the exception to throw.
		}
		//Calculate m = e*((u1^z)^ -1)
		GroupElement invOfU1ExpZ = dlogGroup.getInverse(dlogGroup.exponentiate(cipher.getU1(), privateKey.getPrivateExp5()));
		GroupElement m = dlogGroup.multiplyGroupElements(cipher.getE(), invOfU1ExpZ);
		
		//convert the plaintext element to a byte[], create a plaintext object with the bytes and return it
		byte[] text = dlogGroup.convertGroupElementToByteArray(m);
		plaintext = new BasicPlaintext(text);
		
		return plaintext;
	}
	
}
