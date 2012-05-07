package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.io.IOException;
import java.math.BigInteger;
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
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.bc.BcDlogECFp;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This class performs the El Gamal encryption and decryption scheme.
 * By definition, this encryption scheme is CPA-secure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScElGamal implements ElGamalEnc{
	
	private DlogGroup dlog;					//the underlying DlogGroup
	private ScElGamalPrivateKey privateKey;	//ElGamal private key (contains x)
	private ScElGamalPublicKey publicKey;		//ElGamal public key (contains h)
	private SecureRandom random;			//source of randomness
	private boolean isKeySet = false;
	
	private BigInteger qMinusOne;	//We keep this value to save unnecessary calculations.
	
	
	/**
	 * Default constructor. The default DlogGroup is BcDlogECFp and is initialized with P-192 NIST's curve.
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public ScElGamal() throws IllegalArgumentException, IOException {
		this(new BcDlogECFp("P-192"));
	}

	/**
	 * Constructor that gets a DlogGroup and set it to the underlying group
	 * It lets SCAPI choose the source of randomness.
	 * @param dlogGroup must be DDH secure
	 * @throws UnInitializedException if the given dlog group is not initialized
	 */
	public ScElGamal(DlogGroup dlogGroup) {
		this(dlogGroup, new SecureRandom());
	}
	/**
	 * Constructor that gets a DlogGroup and set it to the underlying group
	 * and gets a source of randomness.
	 * @param dlogGroup must be DDH secure
	 * @param random source of randomness
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level 
	 */
	public ScElGamal(DlogGroup dlogGroup, SecureRandom random) {
		//the underlying dlog group must be DDH secure
		if (!(dlogGroup instanceof DDH)){
			throw new IllegalArgumentException("DlogGroup should have DDH security level");
		}
		dlog = dlogGroup;
		qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		this.random = random;
	}
	
	/**
	 * Constructor that gets a DlogGroup name to create and set it to the underlying group
	 * @param dlogGroup must be DDH secure
	 * @throws FactoriesException if the creation of the dlog failed
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level 
	 */
	public ScElGamal(String dlogName) throws FactoriesException{
		//Create a dlog group object with relevant factory, and then use regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogName));
	}
	
	
	/**
	 * Constructor that gets a DlogGroup name to create and set it to the underlying group
	 * @param dlogGroup must be DDH secure
	 * @throws FactoriesException if the creation of the dlog failed
	 * @throws NoSuchAlgorithmException 
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level 
	 */
	public ScElGamal(String dlogName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		//Create a dlog group object with relevant factory. and then use regular constructor.
		//Creates a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
		//Then use regular constructor.
		this(DlogGroupFactory.getInstance().getObject(dlogName), SecureRandom.getInstance(randNumGenAlg));
	}
	
		/**
	 * Initialize this ElGamal encryption scheme with keys, AlgorithmParameterSpec and source of randomness.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param privateKey should be ElGamalPrivateKey
	 * @param params can be GroupParams to initialize the DlogGroup
	 * @param random source of secure randomness
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey) {
		//key should be ElGamal keys
		if(!(publicKey instanceof ScElGamalPublicKey) || !(privateKey instanceof ScElGamalPrivateKey)){
			throw new IllegalArgumentException("keys should be instances of ElGamal keys");
		}
	
		//set the key
		this.publicKey = (ScElGamalPublicKey) publicKey;
			
		//operates an optimization of the private key
		initPrivateKey(privateKey);
		isKeySet = true;
	}



	/**
	 * Initialize this ElGamal encryption scheme with public key.
	 * Setting only the public key the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be ElGamalPublicKey
	 * @param random source of secure randomness
	 */
	public void setKey(PublicKey publicKey) {
		//public key should be ElGamal public key
		if(!(publicKey instanceof ScElGamalPublicKey)){
			throw new IllegalArgumentException("key should be instances of ElGamal key");
		}
		//set the parameters
		this.publicKey = (ScElGamalPublicKey) publicKey;
		this.privateKey = null;
		isKeySet = true;
	}

	/**
	 * ElGamal decrypt function can be optimized if, instead of using the x value in the private key as is, 
	 * we change it to be q-x, while q is the dlog group order.
	 * This function operates this changing and save the new private value as the private key memeber
	 * @param privateKey to change
	 */
	private void initPrivateKey(PrivateKey privateKey){
		//get the a value from the private key
		BigInteger x = ((ScElGamalPrivateKey) privateKey).getX();
		//get the q-x value
		BigInteger xInv = dlog.getOrder().subtract(x);
		//set the q-x value as the private key
		this.privateKey = new ScElGamalPrivateKey(xInv);
	}
	
	/**
	 * In case that the dlog is not initialized and the init function didn't get a GroupParams to initialize it,
	 * this function initialize it with default values.
	 */
	/*private void initDlogDefault(){
		
		if (dlog instanceof DlogECF2m){
			((DlogECF2m)dlog).init("B-163");
		}
		if (dlog instanceof DlogECFp){
			((DlogECFp)dlog).init("P-192");
		}
		if (dlog instanceof DlogZp){
			BigInteger q = null;
			BigInteger xG = null;
			BigInteger p = null;
			ZpGroupParams params = new ZpGroupParams(q, xG, p);
			try {
				((DlogZp)dlog).init(params);
			} catch (IOException e) {
				// shouldn't occur since that can occur in EC cases
				e.printStackTrace();
			}
		}
	}
	*/
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
	 * Pseudo-code:
	 * 		•	Choose a random  y <- Zq
	 *		•	Calculate c1 = g^y mod p //mod p operation are performed automatically by the group.
	 *		•	Calculate c2 = h^y * plaintext.getText() mod p
	 * @param plaintext contains message to encrypt
	 * @return CipherText of type ElGamalCiphertext contains the encrypted message
	 */
	public Ciphertext encrypt(Plaintext plaintext) {
		//convert the message to a group element. 
		//if the message is not a group element, the function convertByteArrayToGroupElement will throw IllegalArgumentException, which we catch.
		try {
			GroupElement msgElement = dlog.convertByteArrayToGroupElement(((BasicPlaintext)plaintext).getText());
		
			//choose a random value y<-Zq
			BigInteger y = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
			
			//calculate c1 = g^y and c2 = msg * h^y
			GroupElement generator = dlog.getGenerator();
			GroupElement c1 = dlog.exponentiate(generator, y);
			GroupElement hy = dlog.exponentiate(publicKey.getH(), y);
			GroupElement c2 = dlog.multiplyGroupElements(hy, msgElement);
			
			//return an ElGamalCiphertext with c1, c2
			ElGamalCiphertext cipher = new ElGamalCiphertext(c1, c2);
			return cipher;
			
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("the given message is not a valid member in this underlying DlogGroup");
		}
	}

	/**
	 * Decrypts the given ciphertext using ElGamal encryption scheme.
	 * Pseudo-code:
	 * 		•	Calculate s = ciphertext.getC1() ^ privateKey
	 *		•	Calculate the inverse of s: invS =  s ^ -1
	 *		•	Calculate m = ciphertext.getC2() * invS
	 * @param cipherText of type ElGamalCiphertext contains the cipher to decrypt
	 * @return Plaintext contains the decrypted message
	 * @throws KeyException 
	 */
	public Plaintext decrypt(Ciphertext cipher) throws KeyException {
		//if there is no private key, throw exception
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//ciphertext should be ElGamal ciphertext
		if (!(cipher instanceof ElGamalCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of ElGamalCiphertext");
		}
		Plaintext plaintext = null;

		ElGamalCiphertext ciphertext = (ElGamalCiphertext) cipher;
		//calculates s = ciphertext.getC1() ^ x
		GroupElement s = dlog.exponentiate(ciphertext.getC1(), privateKey.getX());
		//calculate the plaintext element m = ciphertext.getC2() * s
		GroupElement m = dlog.multiplyGroupElements(ciphertext.getC2(), s);
		
		//convert the plaintext element to a byte[], create a plaintext object with the bytes and return it
		byte[] text = dlog.convertGroupElementToByteArray(m);
		plaintext = new BasicPlaintext(text);
		
		return plaintext;
	}

	/**
	 * Generates a KeyPair contains set of ElGamalPublicKEy and ElGamalPrivateKey using default source of randomness and the dlog specified upon construction.
	 * @return KeyPair contains keys for this El Gamal object
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey() {
		
		KeyPair pair = null;
		
		//choose a random value in Zq
		BigInteger x = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		GroupElement generator = dlog.getGenerator();
		//calculates h = g^x
		GroupElement h = dlog.exponentiate(generator, x);
		//create an ElGamalPublicKey with h and ElGamalPrivateKey with x
		ScElGamalPublicKey publicKey = new ScElGamalPublicKey(h);
		ScElGamalPrivateKey privateKey = new ScElGamalPrivateKey(x);
		//create a KeyPair with the created keys
		pair = new KeyPair(publicKey, privateKey);
	
		return pair;
	}
	
	/**
	 * There is no need for parameters to generate an El Gamal key pair. Therefore this operation is not supported.
	 * @throws UnsupportedOperationException
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//No need for parameters to generate an El Gamal key pair. Therefore this operation is not supported
		throw new UnsupportedOperationException();
	}
	
	/**
	 * Creates DlogGroup using the ElGamalParameterSpec
	 * @param keyParams ElGamalParameterSpec
	 * @return initialized dlogGroup
	 */
	/*private static DlogGroup createDlogGroup(ElGamalParameterSpec keyParams) {
		try {
			DlogGroup dlog = null;
			String provider = keyParams.getProviderName();
			if (provider == null){
				dlog = DlogGroupFactory.getInstance().getObject(keyParams.getDlogName());
			} else {
				dlog = DlogGroupFactory.getInstance().getObject(keyParams.getDlogName(), provider);
			}
			dlog.init(keyParams.getGroupParams());
			return dlog;
			
		} catch(Exception e){
			
		}
		return null;
	}
	*/
	
	/**
	 * Calculates the ciphertext resulting of multiplying two given ciphertexts.
	 * IF NOT VALID_PARAMS(G,q,g), AND the same h value appears in c1,c2, 
	 * 	REPORT ERROR and HALT
	 * c1 = (u1, v1); c2 = (u2, v2) 
	 * SAMPLE a random value w in Zq
	 * COMPUTE u = g^w*u1*u2
	 * COMPUTE v = h^w*v1*v2
	 * OUTPUT c = (u,v)
	 */
	public Ciphertext multiply(Ciphertext cipher1, Ciphertext cipher2) {
		//TODO Need to decide if the  H element of the public key has to be part of the ciphertext or not.
		//Without that we can't check that both ciphertexts have the same H.
		//TODO Need to decide if the dlog group has to be part of the ciphertext.
		
		//cipher1 and cipher2 should be ElGamal ciphertexts
		if (!(cipher1 instanceof ElGamalCiphertext) || !(cipher2 instanceof ElGamalCiphertext)){
			throw new IllegalArgumentException("ciphertexts should be instance of ElGamalCiphertext");
		}
		ElGamalCiphertext c1 = (ElGamalCiphertext)cipher1;
		ElGamalCiphertext c2 = (ElGamalCiphertext)cipher2;
		
		//choose a random value in Zq
		BigInteger w = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//calculate u = g^w*u1*u2
		GroupElement gExpW = dlog.exponentiate(dlog.getGenerator(), w);
		GroupElement gExpWmultU1 = dlog.multiplyGroupElements(gExpW, c1.getC1());
		GroupElement u = dlog.multiplyGroupElements(gExpWmultU1, c2.getC1());
		
		//calculate v = h^w*v1*v2
		GroupElement hExpW = dlog.exponentiate(publicKey.getH(), w);
		GroupElement hExpWmultV1 = dlog.multiplyGroupElements(hExpW, c1.getC2());
		GroupElement v = dlog.multiplyGroupElements(hExpWmultV1, c2.getC2());
		
		return new ElGamalCiphertext(u,v);
	}

	
	

}
