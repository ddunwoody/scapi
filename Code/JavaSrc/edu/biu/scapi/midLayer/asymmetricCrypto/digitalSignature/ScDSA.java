package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

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
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DSAPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DSAPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDSAPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDSAPublicKey;
import edu.biu.scapi.midLayer.signature.DSASignature;
import edu.biu.scapi.midLayer.signature.Signature;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.ZpElement;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

public class ScDSA implements DSABasedSignature{

	private DSAPublicKey publicKey;
	private DSAPrivateKey privateKey;
	private boolean isKeySet = false;				//set to false until setKey is called
	private CryptographicHash hash;					//the underlying hash to use
	private DlogGroup dlog;							//the underlying DlogGroup to use
	
	private SecureRandom random;
	private BigInteger qMinusOne;	//We keep this value to save unnecessary calculations.
	
	/**
	 * Default constructor. uses SHA1 and SHA1PRNG random number generator algorithm.
	 * @throws FactoriesException
	 * @throws NoSuchAlgorithmException 
	 */
	public ScDSA() throws FactoriesException, NoSuchAlgorithmException{
		//call the other constructor with default parameters
		this("SHA-1", "DlogECFp", "SHA1PRNG");
	}
	
	/**
	 * Constructor that receives hash name and random number generation algorithm to use.
	 * @param hashName underlying hash to use
	 * @param dlog underlying dlogGroup to use
	 * @throws FactoriesException if there is no hash with the given name
	 * @throws NoSuchAlgorithmException if there is no random number generation algorithm
	 */
	public ScDSA(String hashName, String dlogName) throws FactoriesException, NoSuchAlgorithmException{
		//creates hash, dlog and random and call the extended constructor 
		this(CryptographicHashFactory.getInstance().getObject(hashName), DlogGroupFactory.getInstance().getObject(dlogName), new SecureRandom());
	}
	/**
	 * Constructor that receives hash name and random number generation algorithm to use.
	 * @param hashName underlying hash to use
	 * @param dlog underlying dlogGroup to use
	 * @param randNumGenAlg random number generation algorithm to use
	 * @throws FactoriesException if there is no hash with the given name
	 * @throws NoSuchAlgorithmException if there is no random number generation algorithm
	 */
	public ScDSA(String hashName, String dlogName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		//creates hash, dlog and random and call the extended constructor 
		this(CryptographicHashFactory.getInstance().getObject(hashName), DlogGroupFactory.getInstance().getObject(dlogName), SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Constructor that receives hash to use.
	 * @param hash underlying hash to use
	 * @throws FactoriesException if there is no hash with the given name
	 */
	public ScDSA(CryptographicHash hash, DlogGroup dlog) throws FactoriesException {
		//create SecureRandom object and call the other constructor
		this(hash, dlog, new SecureRandom());
	}
	
	/**
	 * Constructor that receives hash and secure random to use.
	 * @param hash underlying hash to use
	 * @param random secure random to use
	 * @throws FactoriesException if there is no hash with the given name
	 */
	public ScDSA(CryptographicHash hash, DlogGroup dlog, SecureRandom random) throws FactoriesException{
		//creates hash with the given name
		this.hash = hash;
		//sets the dlog
		this.dlog = dlog;
		qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		//sets the given random
		this.random = random;
	}
	
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey)
			throws InvalidKeyException {
		//key should be RSA keys
		if(!(publicKey instanceof ScDSAPublicKey)){
			throw new IllegalArgumentException("keys should be instances of ScDSA keys");
		}
		if(privateKey!= null && !(privateKey instanceof ScDSAPrivateKey)){
				throw new IllegalArgumentException("keys should be instances of ScDSA keys");
		}
		//set the parameters
		this.publicKey = (ScDSAPublicKey) publicKey;
		if (privateKey != null){
			this.privateKey = (ScDSAPrivateKey) privateKey;
		}
		
		isKeySet = true;
		
	}

	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		//call the other setKey function with null private key
		setKey(publicKey, null);
		
	}

	@Override
	public boolean isKeySet() {
		
		return isKeySet;
	}

	/**
	 * @return this algorithm name - "RSA/PSS"
	 */
	@Override
	public String getAlgorithmName() {
		
		return "RSA/PSS";
	}

	/**
	 * Signs the given message according to the following algorithm:
	 * 
	 *  o	Choose a random k in Zq
	 *  o	Calculate r = g^k mod q.  
	 *  o	If r = 0, start again with a different random k
	 *	o	Calculate e = H(m), and let z be the Lq leftmost bits of e, where Lq is the bit length of the group order q.
	 *	o	Calculate s = k^(−1)(z + x•r) mod q
	 *	o	If s = 0, start again with a different random k
	 *	o	The signature is (r, s)
	 *
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
		
		BigInteger r = BigInteger.ZERO;
		BigInteger s = BigInteger.ZERO;
		BigInteger k = null;
		BigInteger q = dlog.getOrder();
		//if after calculation s is 0 - start again with a different k
		while(s.equals(BigInteger.ZERO)){
			
			//if after calculation r is 0 - start again with a different k
			while(r.equals(BigInteger.ZERO)){
				//choose a random value in Zq
				k = BigIntegers.createRandomInRange(BigInteger.ONE, qMinusOne, random);
				GroupElement generator = dlog.getGenerator();
				//calculates h = g^x
				GroupElement h = dlog.exponentiate(generator, k);
				//get the BigInteger value of the groupElement
				r = getRFromGroupElement(h);
			}
			
			//compute H(m) and return the left Lq bits of the result as BigInteger
			BigInteger z = hashMsg(msg, offset, length);
			
			//calculate k^-1(z + x•r) mod q
			BigInteger kInv = k.modInverse(q);
			BigInteger xr = (privateKey.getX()).multiply(r);
			s = (z.add(xr)).multiply(kInv);
			s = s.mod(q);
			
		}
		
		//creates DSA signature with r, s
		return new DSASignature(r,s);
	}

	/*
	 * compute H(msg). Returns the left Lq bits of the result as BigInteger
	 */
	private BigInteger hashMsg(byte[] msg, int offset, int length) {
		//get H(msg)
		hash.update(msg, offset, length);
		byte[] hashResult = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(hashResult, 0);
		
		int bitSize = dlog.getOrder().bitLength();
		byte[] e = new byte[bitSize];
		BigInteger z;
		//get the Lq bits of hashResult
		if (hashResult.length > (bitSize/8)){
			System.arraycopy(hashResult, 0, e, 0, bitSize);
			//get the BI representation of e
			z = new BigInteger(e);
		} else {
			//get the BI representation of the hash result
			z = new BigInteger(hashResult);
		}
		
		return z;
	}
	
	/*
	 * Calculates the BigInteger value for the algorithm from the given groupElement.
	 * In case of Zp element, the value is the element itself modulus q
	 * In case of EC point, the value is the x coordinate of the point modulus q
	 */
	private BigInteger getRFromGroupElement(GroupElement element){
		BigInteger r = null;
		//in case of Zp element, r is the element itself
		if (element instanceof ZpElement){
			r = ((ZpElement) element).getElementValue();
		}
		//in case of EC point, r is the x coordinate of the point
		if (element instanceof ECElement){
			r = ((ECElement) element).getX();
		}
		
		//calculate r mod q
		r = r.mod(dlog.getOrder());
		
		return r;
	}

	/**
	 * Verifies the given signatures according to the following algorithm:
	 * 
	 *  o	If r or s is not in Zq, return false
	 *  o	Calculate w = s^(−1) mod q
	 *  o	Calculate e = H(m). Let z be the Lq leftmost bits of e.
	 *  o	Calculate u1 = z•w mod q
	 *  o	Calculate u2 = r•w mod q
	 *  o	Calculate v = g^u1•y^u2. In Zp case, calculate vVal = v mod q. In EC case, Let vVal be the x coordinate of v mod q
	 *  o	If r = vVal return true.

	 * @param signature to verify
	 * @param msg the byte array to verify the signature with
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return true if the signature is valid. false, otherwise.
	 */
	@Override
	public boolean verify(Signature signature, byte[] msg, int offset, int length) {
		
		if (!(signature instanceof DSASignature)){
			throw new IllegalArgumentException("Signature must be instance of DSASignature");
		}
		
		//get r and s from the signature
		BigInteger r = ((DSASignature) signature).getR();
		BigInteger s = ((DSASignature) signature).getS();
		BigInteger q = dlog.getOrder();
		
		//if r not in Zq return false
		if ((r.compareTo(BigInteger.ZERO) <= 0) || (r.compareTo(q) >= 0)){
			return false;
		}
		//if s not in Zq return false
		if ((s.compareTo(BigInteger.ZERO) <= 0) || (s.compareTo(q) >= 0)){
			return false;
		}
		
		//w = s^-1 mod q
		BigInteger w = s.modInverse(q);
		
		//compute H(m) and return the left Lq bits of the result as BigInteger
		BigInteger z = hashMsg(msg, offset, length);
		
		//u1 = z*w mod q
		BigInteger u1 = (z.multiply(w)).mod(q);
		//u2 = r*w mod q
		BigInteger u2 = (r.multiply(w)).mod(q);
		
		//v = g^u1*g^u2
		GroupElement leftElement = dlog.exponentiate(dlog.getGenerator(), u1);
		GroupElement rightElement = dlog.exponentiate(publicKey.getY(), u2);
		GroupElement v = dlog.multiplyGroupElements(leftElement, rightElement);
		//get the BigInteger value of the groupElement
		BigInteger vBI = getRFromGroupElement(v);
		
		if (r.equals(vBI)){
			return true;
		} else {
			return false;
		}
	}

	/**
	 * This function is not supported in this class. 
	 * Use generateKey() instead.
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		throw new UnsupportedOperationException("To generate keys for this RSAPss use generateKey(AlgorithmParameterSpec keyParams) function");
	}

	/**
	 * This function is not supported in this class. 
	 * Use generateKey(AlgorithmParameterSpec keyParams) instead.
	 */
	@Override
	public KeyPair generateKey() {
		KeyPair pair = null;
		 
		//choose a random value in Zq
		BigInteger x = BigIntegers.createRandomInRange(BigInteger.ONE, qMinusOne, random);
		GroupElement generator = dlog.getGenerator();
		//calculates h = g^x
		GroupElement y = dlog.exponentiate(generator, x);
		//create an ScDSAPublicKey with y and ScDSAPrivateKey with x
		ScDSAPublicKey publicKey = new ScDSAPublicKey(y);
		ScDSAPrivateKey privateKey = new ScDSAPrivateKey(x);
		//create a KeyPair with the created keys
		pair = new KeyPair(publicKey, privateKey);
	
		return pair;
	}

	
}
