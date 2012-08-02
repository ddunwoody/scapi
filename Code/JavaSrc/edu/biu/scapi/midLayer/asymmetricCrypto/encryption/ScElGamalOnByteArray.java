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
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPrivateKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnByteArrayCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * This class performs the El Gamal encryption scheme that perform the encryption on a ByteArray.
 * The general encryption of a message usually uses this type of encryption. <p>
 * 
 * By definition, this encryption scheme is CPA-secure and Indistinguishable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScElGamalOnByteArray extends ElGamalAbs{

	private KeyDerivationFunction kdf; 	// The underlying KDF to use in the encryption.
	
	/**
	 * Default constructor. Uses the default implementations of DlogGroup, CryptographicHash and SecureRandom.
	 */
	public ScElGamalOnByteArray(){
		super();
		//Creates a default implementation of KDF.
		setKdf(new HKDF(new BcHMAC()));
	}

	private void setKdf(KeyDerivationFunction kdf){
		this.kdf = kdf;
	}
	
	/**
	 * Constructor that gets a DlogGroup and sets it to the underlying group.
	 * It lets SCAPI choose and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScElGamalOnByteArray(DlogGroup dlogGroup, KeyDerivationFunction kdf) {
		super(dlogGroup, new SecureRandom());
		setKdf(kdf);
	}
	/**
	 * Constructor that gets a DlogGroup and source of randomness.
	 * @param dlogGroup must be DDH secure.
	 * @param random source of randomness.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScElGamalOnByteArray(DlogGroup dlogGroup, KeyDerivationFunction kdf, SecureRandom random) {
		super(dlogGroup, random);
		//Sets the given KDF.
		setKdf(kdf);
	}
	
	/**
	 * Constructor that gets a DlogGroup name to create and sets it to the underlying group.
	 * Uses default implementation of SecureRandom.
	 * @param dlogName must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level. 
	 */
	public ScElGamalOnByteArray(String dlogName, String kdfName) throws FactoriesException{
		super(dlogName);
		//Sets the given KDF.
		setKdf(KdfFactory.getInstance().getObject(kdfName));
	}
	
	
	/**
	 * Constructor that gets a DlogGroup name to create and random number generator to use.
	 * @param dlogName must be DDH secure.
	 * @throws FactoriesException if the creation of the dlog failed.
	 * @throws NoSuchAlgorithmException if the given random number generator is not supported.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScElGamalOnByteArray(String dlogName, String kdfName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		super(dlogName, randNumGenAlg);
		//Sets the given KDF.
		setKdf(KdfFactory.getInstance().getObject(kdfName));
	}
	

	/**
	 * ElGamal decrypt function can be optimized if, instead of using the x value in the private key as is, 
	 * we change it to be q-x, while q is the dlog group order.
	 * This function computes this changing and saves the new private value as the private key member.
	 * @param privateKey to change.
	 */
	protected void initPrivateKey(PrivateKey privateKey){
		//Sets the given PrivateKey.
		this.privateKey = (ElGamalPrivateKey) privateKey;
	}
	
	/**
	 * ElGamalOnByteArray encryption scheme has no limit of the byte array length to generate a plaintext from.
	 * @return false. 
	 */
	public boolean hasMaxByteArrayLengthForPlaintext(){
		return false;
	}
	
	/**
	 * ElGamalOnByteArray encryption can get any plaintext length.
	 * @throws NoMaxException.
	 */
	public int getMaxLengthOfByteArrayForPlaintext(){
		throw new NoMaxException("ElGamalOnByteArray encryption can get any plaintext length");
	}
	
	/**
	 * Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 */
	public Plaintext generatePlaintext(byte[] text){
		
		return new ByteArrayPlaintext(text);
	}
	
	/**
	 * Completes the encryption operation.
	 * @param plaintext contains message to encrypt. MUST be of type ByteArrayPlaintext.
	 * @return Ciphertext of type ElGamalOnByteArrayCiphertext containing the encrypted message.
	 * @throws IllegalArgumentException if the given Plaintext is not an instance of ByteArrayPlaintext.
	 */
	protected AsymmetricCiphertext completeEncryption(GroupElement c1, GroupElement hy, Plaintext plaintext){
		
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of ByteArrayPlaintext");
		}
	
		//Gets the message.
		byte[] msg = ((ByteArrayPlaintext) plaintext).getText();
	
		byte[] hyBytes = dlog.mapAnyGroupElementToByteArray(hy);
		byte[] c2 = kdf.derivateKey(hyBytes, 0, hyBytes.length, msg.length).getEncoded();
		
		//Xores the result from the kdf with the plaintext.
		for(int i=0; i<msg.length; i++){
			c2[i] = (byte) (c2[i] ^ msg[i]);
		}
		
		//Returns an ElGamalOnByteArrayCiphertext with c1, c2.
		return new ElGamalOnByteArrayCiphertext(c1, c2);
	}

	/**
	 * Decrypts the given ciphertext using ElGamal encryption scheme.
	 *
	 * @param cipher MUST be of type ElGamalOnByteArrayCiphertext contains the cipher to decrypt.
	 * @return Plaintext of type ByteArrayPlaintext which containing the decrypted message.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given cipher is not instance of ElGamalOnByteArrayCiphertext.
	 */
	public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException {
		/*  
		 * Pseudo-code:
		 * 	•	Calculate s = ciphertext.getC1() ^ x
		 *	•	Calculate m = KDF(s) XOR ciphertext.getC2() 
		 */
		
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be ElGamal ciphertext.
		if (!(cipher instanceof ElGamalOnByteArrayCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of ElGamalOnByteArrayCiphertext");
		}

		ElGamalOnByteArrayCiphertext ciphertext = (ElGamalOnByteArrayCiphertext) cipher;
		//Calculates s = ciphertext.getC1() ^ x.
		GroupElement s = dlog.exponentiate(ciphertext.getC1(), privateKey.getX());
		byte[] sBytes = dlog.mapAnyGroupElementToByteArray(s);
		byte[] c2 = ciphertext.getC2();
		//Calculates the plaintext element m = KDF(s) ^ c2.
		byte[] m = kdf.derivateKey(sBytes, 0, sBytes.length, c2.length).getEncoded();
		
		//Xores the result from the kdf with the plaintext.
		for(int i=0; i<c2.length; i++){
			m[i] = (byte) (m[i] ^ c2[i]);
		}
		
		//Creates a plaintext object with the element and returns it.
		return new ByteArrayPlaintext(m);
	}

	/**
	 * Generates a byte array from the given plaintext. 
	 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has, 
	 * and therefore he is working on byte array.
	 * @param plaintext to generates byte array from. MUST be an instance of ByteArrayPlaintext.
	 * @return the byte array generated from the given plaintext.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of ByteArrayPlaintext.
	 */
	public byte[] generateBytesFromPlaintext(Plaintext plaintext){
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be an instance of ByteArrayPlaintext");
		}
		
		return ((ByteArrayPlaintext) plaintext).getText();
	}
}
