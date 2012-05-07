/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Vector;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.ScapiRuntimeException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDamgardJurikPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.DJCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.trapdoorPermutation.RSAModulus;
import edu.biu.scapi.primitives.trapdoorPermutation.ScRSAPermutation;
import edu.biu.scapi.tools.math.MathAlgorithms;

/**
 * Damgard Jurik is an asymmetric encryption scheme based on the Paillier encryption scheme.
 * This encryption scheme is CPA-secure and Indistinguishable.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScDamgardJurikEnc implements DamgardJurikEnc {
	
	private DamgardJurikPublicKey publicKey;
	private DamgardJurikPrivateKey privateKey;
	private SecureRandom random;
	private boolean isKeySet = false;


	/**
	 * Default constructor.
	 */
	public ScDamgardJurikEnc(){
		random = new SecureRandom();
	}
	
	/**
	 * Constructor that lets the user choose the source of randomness
	 * @param random
	 */
	public ScDamgardJurikEnc(SecureRandom rnd){
		random = rnd;
	}
	/**
	 * 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#setKey(java.security.PublicKey, java.security.PrivateKey)
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey)	throws InvalidKeyException {
		//public key should be Damgard Jurik public key
		if(!(publicKey instanceof ScDamgardJurikPublicKey)){
			throw new InvalidKeyException("The public key must be of type DamgardJurikPublicKey");
		}
		//Set the public key
		this.publicKey = (ScDamgardJurikPublicKey) publicKey;

		//private key should be Damgard Jurik private key or null if we are only setting the public key.	
		if(privateKey == null){
			//If the private key in the argument is null then this instance's private key should be null.  
			this.privateKey = null;
		}else{
			if(!(privateKey instanceof ScDamgardJurikPrivateKey)){
				throw new InvalidKeyException("The private key must be of type DamgardJurikPrivateKey");
			}
			//Set the private key
			this.privateKey = (ScDamgardJurikPrivateKey) privateKey;
		}
		isKeySet = true;

	}

	/**
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#setKey(java.security.PublicKey)
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		setKey(publicKey, null);

	}

	/**
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#isKeySet()
	 */
	@Override
	public boolean isKeySet() {
		// TODO Auto-generated method stub
		return isKeySet;
	}

	/**
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#getAlgorithmName()
	 */
	@Override
	public String getAlgorithmName() {
		
		return "DamgardJurik";
	}

	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateKey(java.security.spec.AlgorithmParameterSpec)
	 * @param keyParams has to be an instance of DJKeyGenParameterSpec
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams)throws InvalidParameterSpecException {
		if(!(keyParams instanceof DJKeyGenParameterSpec)){
			throw new InvalidParameterSpecException("keyParams has to be an instance of DJKeyGenParameterSpec");
		}
		
		DJKeyGenParameterSpec params = (DJKeyGenParameterSpec)keyParams;
		//Choose an RSA modulus n = p*q of length k bits.
		//Compute t = lcmp(p-1, q-1) where lcm is the least common multiple and can be computed as lcm(a,b) = a*b/gcd(a,b)
		//Let n be the Public Key
		//Let t be the Private Key
		RSAModulus rsaMod = ScRSAPermutation.generateRSAModulus(params.getModulusLength(), params.getCertainty(), random);
		
		BigInteger pMinus1 = rsaMod.p.subtract(BigInteger.ONE);
		BigInteger qMinus1 = rsaMod.q.subtract(BigInteger.ONE);
		BigInteger gcdPMinus1QMinus1 = pMinus1.gcd(qMinus1);
		BigInteger t = (pMinus1.multiply(qMinus1)).divide(gcdPMinus1QMinus1);
		BigInteger dForS1 = generateD(rsaMod.n, t); //precalculate d for the case that s == 1
		
		return new KeyPair(new ScDamgardJurikPublicKey(rsaMod.n), new ScDamgardJurikPrivateKey(t, dForS1));
	}

	/**
	 * This function is not supported for this encryption scheme.
	 * @return 
	 * @throws UnsupportedOperationException
	 */
	public KeyPair generateKey() {
		throw new UnsupportedOperationException("Use generateKey function with DJKeyGenParameterSpec");
	}
	
	/** 
	 * This function performs the encryption of he given plain text
	 * @param plaintext can be an instance of BasicPlaintext or an instance of BigIntegerPlainText.
	 * @return an object of type DJCiphertext holding the encryption of the plaintext.
	 */
	public Ciphertext encrypt(Plaintext plainText) {
		BigInteger x; 
		if(plainText instanceof BasicPlaintext){
			x = new BigInteger(((BasicPlaintext) plainText).getText());
		}
		else if(plainText instanceof BigIntegerPlainText){
			x = ((BigIntegerPlainText)plainText).getX();
		}else{
			throw new IllegalArgumentException("The plaintext has to be either of type BasicPlaintext or of type BigIntegerPlainText");
		}
		int s = (x.bitLength()/publicKey.getModulus().bitLength()) + 1;
		BigInteger N = publicKey.getModulus().pow(s);
		//Make sure the x belongs to ZN
		if(x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(N) >= 0)
			throw new IllegalArgumentException("Message too big for encryption");
		
		BigInteger Ntag = publicKey.getModulus().pow(s+1);
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);

		//Choose a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		//Compute c = ((1 + n) ^x) * r ^N mod N'
		BigInteger  mult1= (publicKey.getModulus().add(BigInteger.ONE)).modPow(x, Ntag);
		BigInteger mult2 = r.modPow(N, Ntag);
		BigInteger c = (mult1.multiply(mult2)).mod(Ntag);

		//Wrap the BigInteger c with DJCiphertext and return it
		return new DJCiphertext(c);
	}

	/**
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#decrypt(edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 * @param cipher has to be an instance of DJCiphertext
	 * @throws KeyException if the Private Key has not been set for this object 
	 * @throws IllegalArgumentException if cipher is not an instance of DJCiphertext
	 */
	@Override
	public Plaintext decrypt(Ciphertext cipher) throws KeyException {
		//if there is no private key, throw exception
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//ciphertext should be Damgard-Jurik ciphertext
		if (!(cipher instanceof DJCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of DJCiphertext");
		}
		
		DJCiphertext djCipher = (DJCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculate s = (|cipher| -1) / |n|
		int s = ((djCipher).getCipher().bitLength() - 1) / publicKey.getModulus().bitLength();

		//Calculate N and N' based on s: N = n^s, N' = n^(s+1)
		BigInteger n = publicKey.getModulus();
		BigInteger N = n.pow(s);
		BigInteger Ntag = n.pow(s+1);
		
		//Make sure the cipher belongs to ZN'
		if(djCipher.getCipher().compareTo(BigInteger.ZERO) < 0 || djCipher.getCipher().compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("The cipher is not in ZN'");
		
		BigInteger d;
		//Optimization for the calculation of d:
		//If s == 1 used the pre-computed d which we have in the private key
		//else, compute d using the Chinese Remainder Theorem, such that d = 1 mod N, and d = 0 mod t.
		if(s==1){
			d = privateKey.getDForS1();
		}else{
			d = generateD(N, privateKey.getT());
		}
		
		//Compute x as the discrete logarithm of c^d to the base (1+n)modulo N'
		//This is done by the following computation
		//	a=c^d
		//	x=0
		//	for j = 1 to s do
		//	begin
		//	   t1= ((a mod n^(j+1) ) -  1) / n
		//	   t2 = x
		//	   for k = 2 to j do
		//	   begin
		//	      x = x – 1
		//	      t2 = t2 * x mod nj
		//	      t1 =  (t1 – (t2 * nk-1) / factorial(k) )  mod nj
		//	  end
		//	  x = t1
		//	end
		//	OUTPUT x
		
		//Compute (cipher ^ d) mod N'
		BigInteger a = djCipher.getCipher().modPow(d, Ntag);  
		BigInteger x = BigInteger.ZERO;
		BigInteger t1, t2;
		for(int j = 1; j <= s; j++){
			t1 = (a.mod(n.pow(j+1)).subtract(BigInteger.ONE)).divide(n);
			t2 = x;
			for(int k = 2; k <=j; k++){
				x = x.subtract(BigInteger.ONE);
				t2 = (t2.multiply(x)).mod(n.pow(j));
				BigInteger factorialK = MathAlgorithms.factorialBI(k);
				BigInteger temp = (t2.multiply(n.pow(k-1))).divide(factorialK);
				t1 = t1.subtract(temp).mod(n.pow(j));
			}
			x = t1;
		}
		
		return new BigIntegerPlainText(x);
	}


	/**
	 * This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but<p>
	 * it is also an encryption of originalPlaintext.
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.DamgardJurikPaillierEnc#reRandomize(edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 */
	@Override
	public Ciphertext reRandomize(Ciphertext cipher) {
		//ciphertext should be Damgard-Jurik ciphertext
		if (!(cipher instanceof DJCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of DJCiphertext");
		}
		
		DJCiphertext djCipher = (DJCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculate s = (|cipher| -1) / |n|
		int s = ((djCipher).getCipher().bitLength() - 1) / publicKey.getModulus().bitLength();

		//Calculate N and N' based on s: N = n^s, N' = n^(s+1)
		BigInteger n = publicKey.getModulus();
		BigInteger N = n.pow(s);
		BigInteger Ntag = n.pow(s+1);
		
		//Make sure the cipher belongs to ZN'
		if(djCipher.getCipher().compareTo(BigInteger.ZERO) < 0 || djCipher.getCipher().compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("The cipher is not in ZN'");
			
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		//Choose a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		BigInteger c = djCipher.getCipher().multiply(r.modPow(N, Ntag));
		
		return new DJCiphertext(c);
	}

	/**
	 * Given two ciphers c1 = Enc(p1)  and c2 = Enc(p2) this function return c1 + c2 = Enc(p1 +p2).
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymAdditiveHomomorphicEnc#add(edu.biu.scapi.midLayer.ciphertext.Ciphertext, edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 */
	@Override
	public Ciphertext add(Ciphertext cipher1, Ciphertext cipher2) {
		//ciphertext should be Damgard-Jurik ciphertext
		if (!(cipher1 instanceof DJCiphertext) || !(cipher1 instanceof DJCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of DJCiphertext");
		}
		DJCiphertext djCipher1 = (DJCiphertext) cipher1;
		DJCiphertext djCipher2 = (DJCiphertext) cipher2;
		//n is the modulus in the public key.
		//Calculate s = (|cipher| -1) / |n|
		int s1 = ((djCipher1).getCipher().bitLength() - 1) / publicKey.getModulus().bitLength();
		int s2 = ((djCipher2).getCipher().bitLength() - 1) / publicKey.getModulus().bitLength();
		if(s1 != s2){
			throw new ScapiRuntimeException("Sizes of ciphertexts do not match");
		}
		
		//Calculate N and N' based on s: N = n^s, N' = n^(s+1)
		BigInteger n = publicKey.getModulus();
		BigInteger N = n.pow(s1);
		BigInteger Ntag = n.pow(s1+1);
		
		//Check that cipher1 and cipher2 belong to ZN'
		if(djCipher1.getCipher().compareTo(BigInteger.ZERO) < 0 || djCipher1.getCipher().compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("cipher1 is not in ZN'");
		if(djCipher2.getCipher().compareTo(BigInteger.ZERO) < 0 || djCipher2.getCipher().compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("cipher2 is not in ZN'");
		
		BigInteger c1 = djCipher1.getCipher();
		BigInteger c2 = djCipher2.getCipher();
		BigInteger c = c1.multiply(c2).mod(Ntag);
		
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		//Choose a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		c = c.multiply(r.modPow(N, Ntag));
		
		return new DJCiphertext(c);
	}

	/**
	 * This function calculates the homomorphic multiplication by a constant of a ciphertext<p>
	 * in the Damgard Jurik encryption scheme.
	 * @param cipher the cipher to operate on
	 * @param constNumber the constant number by which to multiply the cipher
	 * @throws IllegalArgumentException if the cipher is not an instance of DJCiphertext
	 */
	@Override
	public Ciphertext multByConst(Ciphertext cipher, BigInteger constNumber) {
		//ciphertext should be Damgard-Jurik ciphertext
		if (!(cipher instanceof DJCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of DJCiphertext");
		}
		
		DJCiphertext djCipher = (DJCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculate s = (|cipher| -1) / |n|
		int s = ((djCipher).getCipher().bitLength() - 1) / publicKey.getModulus().bitLength();

		//Calculate N and N' based on s: N = n^s, N' = n^(s+1)
		BigInteger n = publicKey.getModulus();
		BigInteger N = n.pow(s);
		BigInteger Ntag = n.pow(s+1);
		
		//Make sure the cipher belongs to ZN'
		if(djCipher.getCipher().compareTo(BigInteger.ZERO) < 0 || djCipher.getCipher().compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("The cipher is not in ZN'");
		
		//Make sure the constant number belongs to ZN
		if(constNumber.compareTo(BigInteger.ZERO) < 0 || constNumber.compareTo(N) >= 0)
			throw new IllegalArgumentException("The constant number is not in ZN");
	
		BigInteger c = djCipher.getCipher().modPow(constNumber, Ntag);
		
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		//Choose a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		c = c.multiply(r.modPow(N, Ntag));
		
		return new DJCiphertext(c);
	}
	
	//This function generates a value d such that d = 1 mod N and d = 0 mod t, using the Chinese Remainder Theorem.
	private BigInteger generateD(BigInteger N, BigInteger t){
		Vector<BigInteger> congruences = new Vector<BigInteger>();
		congruences.add(BigInteger.ONE);
		congruences.add(BigInteger.ZERO);
		Vector<BigInteger> moduli = new Vector<BigInteger>();
		moduli.add(N);
		moduli.add(t);
		BigInteger d = MathAlgorithms.chineseRemainderTheorem(congruences, moduli);
		return d;
	}
	
}

