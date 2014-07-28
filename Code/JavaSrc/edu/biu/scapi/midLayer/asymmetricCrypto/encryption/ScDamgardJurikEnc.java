/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
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
import java.util.Vector;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDamgardJurikPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.trapdoorPermutation.RSAModulus;
import edu.biu.scapi.primitives.trapdoorPermutation.ScRSAPermutation;
import edu.biu.scapi.tools.math.MathAlgorithms;

/**
 * Damgard Jurik is an asymmetric encryption scheme based on the Paillier encryption scheme.
 * This encryption scheme is CPA-secure and Indistinguishable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScDamgardJurikEnc implements DamgardJurikEnc {
	
	private DamgardJurikPublicKey publicKey;
	private DamgardJurikPrivateKey privateKey;
	private SecureRandom random;
	private boolean isKeySet;


	/**
	 * Default constructor. Uses the default implementations of SecureRandom.
	 */
	public ScDamgardJurikEnc(){
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that lets the user choose the source of randomness.
	 * @param rnd source of randomness.
	 */
	public ScDamgardJurikEnc(SecureRandom rnd){
		random = rnd;
	}
	
	/**
	 * Constructor that lets the user choose the random number generation algorithm.
	 * @param randNumGenAlg random number generation algorithm.
	 * @throws NoSuchAlgorithmException if the given name is not a valid random number generation algorithm name.
	 */
	public ScDamgardJurikEnc(String randNumGenAlg) throws NoSuchAlgorithmException{
		this(SecureRandom.getInstance(randNumGenAlg));
	}
	
	/**
	 * Initializes this DamgardJurik encryption scheme with (public, private) key pair.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be DamgardJurikPublicKey.
	 * @param privateKey should be DamgardJurikPrivateKey.
	 * @throws InvalidKeyException if the given keys are not instances of DamgardJurik keys.
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException{
		//Public key should be Damgard Jurik public key.
		if(!(publicKey instanceof DamgardJurikPublicKey)){
			throw new InvalidKeyException("The public key must be of type DamgardJurikPublicKey");
		}
		//Sets the public key
		this.publicKey = (DamgardJurikPublicKey) publicKey;

		//Private key should be Damgard Jurik private key or null if we are only setting the public key.	
		if(privateKey != null){
			
			if(!(privateKey instanceof DamgardJurikPrivateKey)){
				throw new InvalidKeyException("The private key must be of type DamgardJurikPrivateKey");
			}
			//Sets the private key
			this.privateKey = (DamgardJurikPrivateKey) privateKey;
		}
		isKeySet = true;

	}

	/**
	 * Initializes this DamgardJurik encryption scheme with public key.
	 * Setting only the public key the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be DamgardJurikPublicKey
	 * @throws InvalidKeyException if the given key is not instance of DamgardJurikPublicKey.
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		setKey(publicKey, null);
	}

	@Override
	public boolean isKeySet() {
		return isKeySet;
	}
	
	/**
	 * Returns the PublicKey of this DamgardJurik encryption scheme.
	 * This function should not be use to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the DamgardJurikPublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey(){
		if (!isKeySet()){
			throw new IllegalStateException("no PublicKey was set");
		}
		
		return publicKey;
	}

	/**
	 * @return the name of this AsymmetricEnc - DamgardJurik.
	 */
	@Override
	public String getAlgorithmName() {
		
		return "DamgardJurik";
	}
	
	/**
	 * DamgardJurik encryption scheme has no limit of the byte array length to generate a plaintext from.
	 * @return false. 
	 */
	public boolean hasMaxByteArrayLengthForPlaintext(){
		return false;
	}
	
	/**
	 * DamgardJurik encryption can get any plaintext length.
	 * @throws NoMaxException 
	 */
	public int getMaxLengthOfByteArrayForPlaintext() throws NoMaxException{
		throw new NoMaxException("DamgardJurik encryption can get any plaintext length");
	}
	
	/**
	 * Generates a Plaintext suitable to DamgardJurik encryption scheme from the given message.
	 * @param msg byte array to convert to a Plaintext object.
	 */
	public Plaintext generatePlaintext(byte[] msg){
		return new BigIntegerPlainText(new BigInteger(msg));
	}

	/**
	 * Generate an DamgardJurik key pair using the given parameters.
	 * @param keyParams MUST be an instance of DJKeyGenParameterSpec.
	 * @return KeyPair contains keys for this DamgardJurik encryption object.
	 * @throws InvalidParameterSpecException if keyParams is not instance of DJKeyGenParameterSpec.
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException{
		if(!(keyParams instanceof DJKeyGenParameterSpec)){
			throw new InvalidParameterSpecException("keyParams has to be an instance of DJKeyGenParameterSpec");
		}
		
		DJKeyGenParameterSpec params = (DJKeyGenParameterSpec)keyParams;
		//Chooses an RSA modulus n = p*q of length k bits.
		//Let n be the Public Key.
		//Let rsaMod be the Private Key.
		
		RSAModulus rsaMod = ScRSAPermutation.generateRSAModulus(params.getModulusLength(), params.getCertainty(), random);
		
		return new KeyPair(new ScDamgardJurikPublicKey(rsaMod.n), new ScDamgardJurikPrivateKey(rsaMod));
	}

	/**
	 * This function is not supported for this encryption scheme, since there is a need for parameters to generate a DamgardJurik key pair.
	 * @throws UnsupportedOperationException
	 */
	public KeyPair generateKey() {
		throw new UnsupportedOperationException("Use generateKey function with DJKeyGenParameterSpec");
	}
	
	/** 
	 * This function performs the encryption of he given plain text
	 * @param plainText MUST be an instance of BigIntegerPlainText.
	 * @return an object of type BigIntegerCiphertext holding the encryption of the plaintext.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If the given plaintext is not instance of BigIntegerPlainText.
	 * 		2. If the BigInteger value in the given plaintext is not in ZN.
	 */
	public AsymmetricCiphertext encrypt(Plaintext plaintext) {
		/*
		 * We use the notation N=n^s, and N’ = n^(s+1).
		 * Pseudo-Code:
		 * 		COMPUTE s=(|x|/(|n|-1)) + 1.
		 * 		CHOOSE a random r in ZN’*.	
		 */
		
		if(!(plaintext instanceof BigIntegerPlainText)){
			throw new IllegalArgumentException("The plaintext has to be of type BigIntegerPlainText");
		}
		
		BigInteger x = ((BigIntegerPlainText)plaintext).getX();
		
		//Calculates the length parameter s.
		int s = (x.bitLength()/(publicKey.getModulus().bitLength() - 1)) + 1;
		
		BigInteger Ntag = publicKey.getModulus().pow(s+1);
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		//Chooses a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*.
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		
		return encrypt(plaintext, r);
	}
	
	/** 
	 * Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.<p>
	 * There are cases when the random value is used after the encryption, for example, in sigma protocol. 
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user 
	 * since this can cause problems when more than one value is being encrypt. 
	 * Instead, we decided to have an additional encrypt value that gets the random value from the user.
	 * @param plainText message to encrypt
	 * @param r The random value to use in the encryption. 
	 * @param plainText MUST be an instance of BigIntegerPlainText.
	 * @return an object of type BigIntegerCiphertext holding the encryption of the plaintext.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If the given plaintext is not instance of BigIntegerPlainText.
	 * 		2. If the BigInteger value in the given plaintext is not in ZN.
	 */
	public AsymmetricCiphertext encrypt(Plaintext plainText, BigInteger r) {
		/*
		 * We use the notation N=n^s, and N’ = n^(s+1).
		 * Pseudo-Code:
		 * 		COMPUTE s=(|x|/(|n|-1)) + 1.
		 * 		CHECK that x is in ZN.
		 *		COMPUTE c = (1+n)^x * r^N mod N’.
		 * 		OUTPUT c.
		 */
		
		// If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		
		if(!(plainText instanceof BigIntegerPlainText)){
			throw new IllegalArgumentException("The plaintext has to be of type BigIntegerPlainText");
		}
		
		
		BigInteger x = ((BigIntegerPlainText)plainText).getX();
		
		//Calculates the length parameter s.
		int s = (x.bitLength()/(publicKey.getModulus().bitLength() - 1)) + 1;
		
		BigInteger N = publicKey.getModulus().pow(s);
		
		//Makes sure the x belongs to ZN
		if(x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(N) >= 0)
			throw new IllegalArgumentException("Message too big for encryption");
		
		BigInteger Ntag = publicKey.getModulus().pow(s+1);
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		
		//Check that the random value passed to this function is in Zq.
		if(!((r.compareTo(BigInteger.ZERO))>=0) && (r.compareTo(NtagMinus1)<=0)) {
			throw new IllegalArgumentException("r must be in Zq");
		}
		
		//Computes c = ((1 + n) ^x) * r ^N mod N'.
		BigInteger  mult1= (publicKey.getModulus().add(BigInteger.ONE)).modPow(x, Ntag);
		BigInteger mult2 = r.modPow(N, Ntag);
		BigInteger c = (mult1.multiply(mult2)).mod(Ntag);
		
		//Wraps the BigInteger c with BigIntegerCiphertext and returns it.
		return new BigIntegerCiphertext(c);
		
	}

	/**
	 * Decrypts the given ciphertext using DamgardJurik encryption scheme.
	 * @param cipher has to be an instance of BigIntegerCiphertext.
	 * @throws KeyException if the Private Key has not been set for this object.
	 * @throws IllegalArgumentException if cipher is not an instance of BigIntegerCiphertext.
	 */
	@Override
	public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException{
		/*
		 * We use the notation N=n^s, and N’ = n^(s+1).
		 * Pseudo-Code:
		 * 		COMPUTE s=|c| / |n|
		 * 		CHECK that c is in ZN'.
		 * 		COMPUTE using the Chinese Remainder Theorem a value d, such that d = 1 mod N, and d=0 mod t. 
		 *		COMPUTE c^d mod N’.
		 *		COMPUTE x as the discrete logarithm of c^d to the base (1+n) modulo N’. This is done by the following computation
		 *	 	a=c^d
		 *		x=0
		 *		for j = 1 to s do
		 *		begin
		 *		   t1= ((a mod n^(j+1)) -  1) / n
		 *		   t2 = x
		 *		   for k = 2 to j do
		 *		   begin
		 *		      x = x – 1
		 *		      t2 = t2 * x mod nj
		 *		      t1 =  (t1 – (t2 * n^(k-1)) / factorial(k) )  mod n^j
		 *		  end
		 *		  x = t1
		 *		end
		 *		OUTPUT x
		 */
		
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be Damgard-Jurik ciphertext.
		if (!(cipher instanceof BigIntegerCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of BigIntegerCiphertext");
		}
		
		BigIntegerCiphertext djCipher = (BigIntegerCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculates s = |cipher| / |n|
		int s = (djCipher).getCipher().bitLength() / publicKey.getModulus().bitLength();

		//Calculates N and N' based on s: N = n^s, N' = n^(s+1)
		BigInteger n = publicKey.getModulus();
		BigInteger N = n.pow(s);
		BigInteger Ntag = n.pow(s+1);
		
		//Makes sure the cipher belongs to ZN'
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
		
		//Computes (cipher ^ d) mod N'
		BigInteger a = djCipher.getCipher().modPow(d, Ntag);
		
		//Computes x as the discrete logarithm of c^d to the base (1+n) modulo N’. This is done by the algorithm shown above.
		BigInteger x = BigInteger.ZERO;
		BigInteger t1, t2;
		BigInteger nPowJ, factorialK, temp;
		for(int j = 1; j <= s; j++){
			t1 = (a.mod(n.pow(j+1)).subtract(BigInteger.ONE)).divide(n);
			t2 = x;
			nPowJ = n.pow(j);
			for(int k = 2; k <=j; k++){
				x = x.subtract(BigInteger.ONE);
				t2 = (t2.multiply(x)).mod(nPowJ);
				factorialK = MathAlgorithms.factorialBI(k);
				temp = (t2.multiply(n.pow(k-1))).divide(factorialK);
				t1 = t1.subtract(temp).mod(nPowJ);
			}
			x = t1;
		}
		
		return new BigIntegerPlainText(x);
	}

	/**
	 * Generates a byte array from the given plaintext. 
	 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has, 
	 * and therefore he is working on byte array.
	 * @param plaintext to generates byte array from. MUST be an instance of BigIntegerPlainText.
	 * @return the byte array generated from the given plaintext.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of BigIntegerPlainText.
	 */
	public byte[] generateBytesFromPlaintext(Plaintext plaintext){
		if (!(plaintext instanceof BigIntegerPlainText)){
			throw new IllegalArgumentException("the given plaintext should be an instance of BigIntegerPlainText");
		}
		
		return ((BigIntegerPlainText) plaintext).getX().toByteArray();
	}
	
	/**
	 * This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but
	 * it is also an encryption of originalPlaintext.<p>
	 * The given ciphertext have to has been generated with the same public key as this encryption's public key.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If cipher is not an instance of BigIntegerCiphertext.
	 * 		2. If the BigInteger number in the given cipher is not in ZN'.
	 */
	@Override
	public AsymmetricCiphertext reRandomize(AsymmetricCiphertext cipher) {
		// If there is no public key can not operate the function, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to reRandomize a ciphertext this object must be initialized with public key");
		}
		
		//Ciphertext should be Damgard-Jurik ciphertext.
		if (!(cipher instanceof BigIntegerCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of BigIntegerCiphertext");
		}
		
		BigIntegerCiphertext djCipher = (BigIntegerCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculates s = |cipher| / |n|.
		int s = (djCipher).getCipher().bitLength() / publicKey.getModulus().bitLength();

		//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
		BigInteger n = publicKey.getModulus();
		BigInteger Ntag = n.pow(s+1);
		
		
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		//Chooses a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*.
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		
		return reRandomize(cipher, r);
	}
	
	/**
	 * This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but
	 * it is also an encryption of originalPlaintext. It uses the given BigInteger random value.<p>
	 * The given ciphertext have to has been generated with the same public key as this encryption's public key.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If cipher is not an instance of BigIntegerCiphertext.
	 * 		2. If the BigInteger number in the given cipher is not in ZN'.
	 */
	@Override
	public AsymmetricCiphertext reRandomize(AsymmetricCiphertext cipher, BigInteger r) {
		// If there is no public key can not operate the function, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to reRandomize a ciphertext this object must be initialized with public key");
		}
		
		//Ciphertext should be Damgard-Jurik ciphertext.
		if (!(cipher instanceof BigIntegerCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of BigIntegerCiphertext");
		}
		
		BigIntegerCiphertext djCipher = (BigIntegerCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculates s = |cipher| / |n|.
		int s = (djCipher).getCipher().bitLength() / publicKey.getModulus().bitLength();

		//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
		BigInteger n = publicKey.getModulus();
		BigInteger N = n.pow(s);
		BigInteger Ntag = n.pow(s+1);
		
		//Makes sure the cipher belongs to ZN'.
		if(djCipher.getCipher().compareTo(BigInteger.ZERO) < 0 || djCipher.getCipher().compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("The cipher is not in ZN'");
		
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		//Check that the r random value passed to this function is in Zntag*.
		if(!((r.compareTo(BigInteger.ZERO))>=0) && (r.compareTo(NtagMinus1)<=0)) {
			throw new IllegalArgumentException("r must be in Zq");
		}
				
		BigInteger c = djCipher.getCipher().multiply(r.modPow(N, Ntag)).mod(Ntag);
		
		return new BigIntegerCiphertext(c);
	}

	/**
	 * Given two ciphers c1 = Enc(p1)  and c2 = Enc(p2) this function return c1 + c2 = Enc(p1 +p2).
	 * Both ciphertext have to have been generated with the same public key as this encryption's public key.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If one or more of the given ciphertexts is not an instance of BigIntegerCiphertext.
	 * 		2. If the sizes of ciphertexts do not match.
	 * 		3. If one or more of the BigInteger numbers in the given ciphertexts is not in ZN'.
	 */
	@Override
	public AsymmetricCiphertext add(AsymmetricCiphertext cipher1, AsymmetricCiphertext cipher2) {
		// If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to add ciphertexts this object must be initialized with public key");
		}
		
		//Ciphertexts should be Damgard-Jurik ciphertexts.
		if (!(cipher1 instanceof BigIntegerCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of BigIntegerCiphertext");
		}
		BigIntegerCiphertext djCipher1 = (BigIntegerCiphertext) cipher1;
		
		BigInteger c = djCipher1.getCipher();
		
		//n is the modulus in the public key.
		//Calculates s = |cipher|/ |n|.
		int s = c.bitLength() / publicKey.getModulus().bitLength();
		
		//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
		BigInteger n = publicKey.getModulus();
		BigInteger Ntag = n.pow(s+1);
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		
		//Chooses a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*.
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		
		return add(cipher1, cipher2, r);
	}
	
	/**
	 * Given two ciphers c1 = Enc(p1)  and c2 = Enc(p2) this function return c1 + c2 = Enc(p1 +p2).<p>
	 * Both ciphertext have to have been generated with the same public key as this encryption's public key.<p>
	 * 
	 * There are cases when the random value is used after the function, for example, in sigma protocol. 
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user 
	 * since this can cause problems when the add function is called more than one time. 
	 * Instead, we decided to have an additional add function that gets the random value from the user.
	 * 
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If one or more of the given ciphertexts is not an instance of BigIntegerCiphertext.
	 * 		2. If the sizes of ciphertexts do not match.
	 * 		3. If one or more of the BigInteger numbers in the given ciphertexts is not in ZN'.
	 */
	@Override
	public AsymmetricCiphertext add(AsymmetricCiphertext cipher1, AsymmetricCiphertext cipher2, BigInteger r) {
		
		// If there is no public key can not operate the function, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to add ciphertexts this object must be initialized with public key");
		}
		
		//Ciphertexts should be Damgard-Jurik ciphertexts.
		if (!(cipher1 instanceof BigIntegerCiphertext) || !(cipher2 instanceof BigIntegerCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of BigIntegerCiphertext");
		}
		BigIntegerCiphertext djCipher1 = (BigIntegerCiphertext) cipher1;
		BigIntegerCiphertext djCipher2 = (BigIntegerCiphertext) cipher2;
		
		BigInteger c1 = djCipher1.getCipher();
		BigInteger c2 = djCipher2.getCipher();
				
		//n is the modulus in the public key.
		//Calculates s = |cipher|/ |n|.
		int s1 = c1.bitLength() / publicKey.getModulus().bitLength();
		int s2 = c2.bitLength() / publicKey.getModulus().bitLength();
		if(s1 != s2){
			throw new IllegalArgumentException("Sizes of ciphertexts do not match");
		}
		
		//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
		BigInteger n = publicKey.getModulus();
		BigInteger N = n.pow(s1);
		BigInteger Ntag = n.pow(s1+1);
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		
		//Check that the r random value passed to this function is in Zntag*.
		if(!((r.compareTo(BigInteger.ZERO))>=0) && (r.compareTo(NtagMinus1)<=0)) {
			throw new IllegalArgumentException("r must be in Zq");
		}
		
		//Checks that cipher1 and cipher2 belong to ZN'
		if(c1.compareTo(BigInteger.ZERO) < 0 || c1.compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("cipher1 is not in ZN'");
		if(c2.compareTo(BigInteger.ZERO) < 0 || c2.compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("cipher2 is not in ZN'");
		
		BigInteger c = c1.multiply(c2).mod(Ntag);
		
		c = c.multiply(r.modPow(N, Ntag)).mod(Ntag);
		
		//Call the other function that computes the addition.
		return new BigIntegerCiphertext(c);
	}

	/**
	 * This function calculates the homomorphic multiplication by a constant of a ciphertext<p>
	 * in the Damgard Jurik encryption scheme.
	 * @param cipher the cipher to operate on.
	 * @param constNumber the constant number by which to multiply the cipher.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If the given cipher is not an instance of BigIntegerCiphertext.
	 * 		2. If the BigInteger numbers in the given ciphertext is not in ZN'.
	 * 		3. If the constant number is not in ZN.
	 */
	@Override
	public AsymmetricCiphertext multByConst(AsymmetricCiphertext cipher, BigInteger constNumber) {
		// If there is no public key can not operate the function, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to multiply a ciphertext this object must be initialized with public key");
		}
		
		//Ciphertext should be Damgard-Jurik ciphertext.
		if (!(cipher instanceof BigIntegerCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of BigIntegerCiphertext");
		}
		
		BigIntegerCiphertext djCipher = (BigIntegerCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculates s = |cipher| / |n|.
		int s = (djCipher).getCipher().bitLength() / publicKey.getModulus().bitLength();
				
		//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
		BigInteger n = publicKey.getModulus();
		BigInteger Ntag = n.pow(s+1);
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		
		//Chooses a random r in ZNtag*, this can be done by choosing a random value between 1 and Ntag -1 
		//which is with overwhelming probability in Zntag*.
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ONE, NtagMinus1, random);
		
		//Call the other function that computes the multiplication.
		return multByConst(cipher, constNumber, r);
	}
	
	/**
	 * This function calculates the homomorphic multiplication by a constant of a ciphertext
	 * in the Damgard Jurik encryption scheme.<p>
	 * 
	 * There are cases when the random value is used after the function, for example, in sigma protocol. 
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user 
	 * since this can cause problems when the add function is called more than one time. 
	 * Instead, we decided to have an additional add function that gets the random value from the user.
	 * 
	 * @param cipher the cipher to operate on.
	 * @param constNumber the constant number by which to multiply the cipher.
	 * @param r The random value to use in the function.
	 * 
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException in the following cases:
	 * 		1. If the given cipher is not an instance of BigIntegerCiphertext.
	 * 		2. If the BigInteger numbers in the given ciphertext is not in ZN'.
	 * 		3. If the constant number is not in ZN.
	 */
	@Override
	public AsymmetricCiphertext multByConst(AsymmetricCiphertext cipher, BigInteger constNumber, BigInteger r) {
		// If there is no public key can not operate the function, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to multiply a ciphertext this object must be initialized with public key");
		}
		
		//Ciphertext should be Damgard-Jurik ciphertext.
		if (!(cipher instanceof BigIntegerCiphertext)){
			throw new IllegalArgumentException("cipher should be instance of BigIntegerCiphertext");
		}
		
		BigIntegerCiphertext djCipher = (BigIntegerCiphertext) cipher;
		//n is the modulus in the public key.
		//Calculates s = |cipher| / |n|.
		int s = (djCipher).getCipher().bitLength() / publicKey.getModulus().bitLength();

		//Calculates N and N' based on s: N = n^s, N' = n^(s+1).
		BigInteger n = publicKey.getModulus();
		BigInteger N = n.pow(s);
		BigInteger Ntag = n.pow(s+1);
		BigInteger NtagMinus1 = Ntag.subtract(BigInteger.ONE);
		
		//Check that the r random value passed to this function is in Zntag*.
		if(!((r.compareTo(BigInteger.ZERO))>=0) && (r.compareTo(NtagMinus1)<=0)) {
			throw new IllegalArgumentException("r must be in Zq");
		}
				
		//Makes sure the cipher belongs to ZN'.
		if(djCipher.getCipher().compareTo(BigInteger.ZERO) < 0 || djCipher.getCipher().compareTo(Ntag) >= 0)
			throw new IllegalArgumentException("The cipher is not in ZN'");
		
		//Makes sure the constant number belongs to ZN.
		if(constNumber.compareTo(BigInteger.ZERO) < 0 || constNumber.compareTo(N) >= 0)
			throw new IllegalArgumentException("The constant number is not in ZN");
	
		BigInteger c = djCipher.getCipher().modPow(constNumber, Ntag);
		
		c = c.multiply(r.modPow(N, Ntag)).mod(Ntag);
		
		return new BigIntegerCiphertext(c);
	}
	
	/**
	 * This function generates a value d such that d = 1 mod N and d = 0 mod t, using the Chinese Remainder Theorem.
	 */
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

	/** 
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 @deprecated As of SCAPI-V1-0-2-2 use reconstructCiphertext(AsymmetricCiphertextSendableData data)
	 */
	@Override
	@Deprecated public AsymmetricCiphertext generateCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof BigIntegerCiphertext))
			throw new IllegalArgumentException("The input data has to be of type BigIntegerCiphertext");

		return (BigIntegerCiphertext) data;
	}
	
	/**
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 */
	@Override
	public AsymmetricCiphertext reconstructCiphertext(AsymmetricCiphertextSendableData data) {
		if(! (data instanceof BigIntegerCiphertext))
			throw new IllegalArgumentException("The input data has to be of type BigIntegerCiphertext");

		return (BigIntegerCiphertext) data;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructPublicKey(edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData)
	 */
	@Override
	public PublicKey reconstructPublicKey(KeySendableData data) {
		if(! (data instanceof DamgardJurikPublicKey))
			throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type DamgardJurikPublicKey");
	return (DamgardJurikPublicKey)data;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructPrivateKey(edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData)
	 */
	@Override
	public PrivateKey reconstructPrivateKey(KeySendableData data) {
		if(! (data instanceof DamgardJurikPrivateKey))
			throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type DamgardJurikPrivateKey");
	return (DamgardJurikPrivateKey)data;
	}
	
}

