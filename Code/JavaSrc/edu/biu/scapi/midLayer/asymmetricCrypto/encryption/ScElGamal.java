package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.io.IOException;
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
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalCiphertext;
import edu.biu.scapi.midLayer.plaintext.GroupElementPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECFp;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This class performs the El Gamal encryption scheme.
 * By definition, this encryption scheme is CPA-secure and Indistinguishable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScElGamal implements ElGamalEnc{
	
	private DlogGroup dlog;						//The underlying DlogGroup
	private ScElGamalPrivateKey privateKey;		//ElGamal private key (contains x)
	private ScElGamalPublicKey publicKey;		//ElGamal public key (contains h)
	private SecureRandom random;				//Source of randomness
	private boolean isKeySet;
	private BigInteger qMinusOne;				//We keep this value to save unnecessary calculations.
	
	
	/**
	 * Default constructor. Uses the default implementations of DlogGroup, CryptographicHash and SecureRandom.
	 */
	public ScElGamal(){
		try {
			dlog = new MiraclDlogECFp("P-192");
		} catch (IOException e) {
			e.printStackTrace();
		}
		qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		this.random = new SecureRandom();
	}

	/**
	 * Constructor that gets a DlogGroup and sets it to the underlying group.
	 * It lets SCAPI choose and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScElGamal(DlogGroup dlogGroup) {
		this(dlogGroup, new SecureRandom());
	}
	/**
	 * Constructor that gets a DlogGroup and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @param random source of randomness.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScElGamal(DlogGroup dlogGroup, SecureRandom random) {
		//The underlying dlog group must be DDH secure.
		if (!(dlogGroup instanceof DDH)){
			throw new IllegalArgumentException("DlogGroup should have DDH security level");
		}
		dlog = dlogGroup;
		qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		this.random = random;
	}
	
	/**
	 * Constructor that gets a DlogGroup name to create and sets it to the underlying group.
	 * Uses default implementation of SecureRandom.
	 * @param dlogGroup must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level. 
	 */
	public ScElGamal(String dlogName) throws FactoriesException{
		//Create a dlog group object with relevant factory, and then use regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogName));
	}
	
	
	/**
	 * Constructor that gets a DlogGroup name to create and random number generator to use.
	 * @param dlogGroup must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws NoSuchAlgorithmException if the given random number generator is not supported.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScElGamal(String dlogName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		//Creates a dlog group object with relevant factory.
		//Creates a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
		//Then use regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogName), SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Initializes this ElGamal encryption scheme with (public, private) key pair.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be ElGamalPublicKey.
	 * @param privateKey should be ElGamalPrivateKey.
	 * @throws InvalidKeyException if the given keys are not instances of ElGamal keys.
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException{
		//Key should be ElGamalPublicKey.
		if(!(publicKey instanceof ScElGamalPublicKey)){
			throw new InvalidKeyException("keys should be instances of ElGamal keys");
		}
		
		//Key should be ElGamalPrivateKey.
		if(privateKey!= null && !(privateKey instanceof ScElGamalPrivateKey)){
			throw new InvalidKeyException("keys should be instances of ElGamal keys");
		}
		
		//Sets the keys.
		this.publicKey = (ScElGamalPublicKey) publicKey;
		
		if (privateKey != null){
			//Computes an optimization of the private key.
			initPrivateKey(privateKey);
		}
		
		isKeySet = true;
	}
	
	/**
	 * Initializes this ElGamal encryption scheme with public key.
	 * Setting only the public key the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @throws InvalidKeyException if the given key is not instances of ElGamalPuclicKey.
	 */
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		setKey(publicKey, null);
	}

	/**
	 * ElGamal decrypt function can be optimized if, instead of using the x value in the private key as is, 
	 * we change it to be q-x, while q is the dlog group order.
	 * This function computes this changing and saves the new private value as the private key member.
	 * @param privateKey to change.
	 */
	private void initPrivateKey(PrivateKey privateKey){
		//Gets the a value from the private key.
		BigInteger x = ((ScElGamalPrivateKey) privateKey).getX();
		//Gets the q-x value.
		BigInteger xInv = dlog.getOrder().subtract(x);
		//Sets the q-x value as the private key.
		this.privateKey = new ScElGamalPrivateKey(xInv);
	}
	
	@Override
	public boolean isKeySet(){
		return isKeySet;
	}
	
	/**
	 * @return the name of this AsymmetricEnc - ElGamal and the underlying dlog group type
	 */
	public String getAlgorithmName(){
		return "ElGamal/"+dlog.getGroupType();
	}
	
	/**
	 * Encrypts the given message using ElGamal encryption scheme.
	 * 
	 * @param plaintext contains message to encrypt. MUST be an instance of GroupElementPlaintext.
	 * @return Ciphertext of type ElGamalCiphertext containing the encrypted message.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext is not instance of GroupElementPlaintext.
	 */
	public Ciphertext encrypt(Plaintext plaintext) {
		/* 
		 * Pseudo-code:
		 * 	•	Choose a random  y <- Zq.
		 *	•	Calculate c1 = g^y mod p //Mod p operation are performed automatically by the group.
		 *	•	Calculate c2 = h^y * plaintext.getText() mod p.
		 */
		
		// If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		
		if (!(plaintext instanceof GroupElementPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of GroupElementPlaintext");
		}
	
		//Gets the element.
		GroupElement msgElement = ((GroupElementPlaintext) plaintext).getElement();
	
		//Chooses a random value y<-Zq.
		BigInteger y = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Calculates c1 = g^y and c2 = msg * h^y.
		GroupElement generator = dlog.getGenerator();
		GroupElement c1 = dlog.exponentiate(generator, y);
		GroupElement hy = dlog.exponentiate(publicKey.getH(), y);
		GroupElement c2 = dlog.multiplyGroupElements(hy, msgElement);
		
		//Returns an ElGamalCiphertext with c1, c2.
		ElGamalCiphertext cipher = new ElGamalCiphertext(c1, c2);
		return cipher;
		
	}

	/**
	 * Decrypts the given ciphertext using ElGamal encryption scheme.
	 *
	 * @param CipherText MUST be of type ElGamalCiphertext contains the cipher to decrypt.
	 * @return Plaintext of type GroupElementPlaintext which containing the decrypted message.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given cipher is not instance of ElGamalCiphertext.
	 */
	public Plaintext decrypt(Ciphertext cipher) throws KeyException {
		/*  
		 * Pseudo-code:
		 * 	•	Calculate s = ciphertext.getC1() ^ x^(-1) //x^(-1) is kept in the private key because of the optimization computed in the function initPrivateKey.
		 *	•	Calculate m = ciphertext.getC2() * s
		 */
		
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be ElGamal ciphertext.
		if (!(cipher instanceof ElGamalCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of ElGamalCiphertext");
		}

		ElGamalCiphertext ciphertext = (ElGamalCiphertext) cipher;
		//Calculates s = ciphertext.getC1() ^ x.
		GroupElement s = dlog.exponentiate(ciphertext.getC1(), privateKey.getX());
		//Calculates the plaintext element m = ciphertext.getC2() * s.
		GroupElement m = dlog.multiplyGroupElements(ciphertext.getC2(), s);
		
		//Creates a plaintext object with the element and returns it.
		Plaintext plaintext = new GroupElementPlaintext(m);
		return plaintext;
	}

	/**
	 * Generates a KeyPair containing a set of ElGamalPublicKEy and ElGamalPrivateKey using the source of randomness and the dlog specified upon construction.
	 * @return KeyPair contains keys for this ElGamal object.
	 */
	public KeyPair generateKey() {
		
		//Chooses a random value in Zq.
		BigInteger x = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		GroupElement generator = dlog.getGenerator();
		//Calculates h = g^x.
		GroupElement h = dlog.exponentiate(generator, x);
		//Creates an ElGamalPublicKey with h and ElGamalPrivateKey with x.
		ScElGamalPublicKey publicKey = new ScElGamalPublicKey(h);
		ScElGamalPrivateKey privateKey = new ScElGamalPrivateKey(x);
		//Creates a KeyPair with the created keys.
		KeyPair pair = new KeyPair(publicKey, privateKey);
		return pair;
	}
	
	/**
	 * This function is not supported for this encryption scheme, since there is no need for parameters to generate an ElGamal key pair.
	 * @throws UnsupportedOperationException
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//No need for parameters to generate an El Gamal key pair. 
		throw new UnsupportedOperationException("To Generate ElGamal keys use the generateKey() function");
	}
	
	/**
	 * Calculates the ciphertext resulting of multiplying two given ciphertexts.
	 * Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If one or more of the given ciphertexts is not instance of ElGamalCiphertext.
	 * 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	 */
	public Ciphertext multiply(Ciphertext cipher1, Ciphertext cipher2) {
		/* 
		 * Pseudo-Code:
		 * 	c1 = (u1, v1); c2 = (u2, v2) 
		 * 	SAMPLE a random value w in Zq
		 * 	COMPUTE u = g^w*u1*u2
		 * 	COMPUTE v = h^w*v1*v2
		 * 	OUTPUT c = (u,v)
		 */
		// Cipher1 and cipher2 should be ElGamal ciphertexts.
		if (!(cipher1 instanceof ElGamalCiphertext) || !(cipher2 instanceof ElGamalCiphertext)){
			throw new IllegalArgumentException("ciphertexts should be instance of ElGamalCiphertext");
		}
		ElGamalCiphertext c1 = (ElGamalCiphertext)cipher1;
		ElGamalCiphertext c2 = (ElGamalCiphertext)cipher2;
		
		//Gets the groupElements of the ciphers.
		GroupElement u1 = c1.getC1();
		GroupElement v1 = c1.getC2();
		GroupElement u2 = c2.getC1();
		GroupElement v2 = c2.getC2();
		
		if (!(dlog.isMember(u1)) || !(dlog.isMember(v1)) || !(dlog.isMember(u2)) || !(dlog.isMember(v2))){
			throw new IllegalArgumentException("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog.getGroupType());
		}
		//Chooses a random value in Zq.
		BigInteger w = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Calculates u = g^w*u1*u2.
		GroupElement gExpW = dlog.exponentiate(dlog.getGenerator(), w);
		GroupElement gExpWmultU1 = dlog.multiplyGroupElements(gExpW, c1.getC1());
		GroupElement u = dlog.multiplyGroupElements(gExpWmultU1, c2.getC1());
		
		//Calculates v = h^w*v1*v2.
		GroupElement hExpW = dlog.exponentiate(publicKey.getH(), w);
		GroupElement hExpWmultV1 = dlog.multiplyGroupElements(hExpW, c1.getC2());
		GroupElement v = dlog.multiplyGroupElements(hExpWmultV1, c2.getC2());
		
		return new ElGamalCiphertext(u,v);
	}

	
	

}
