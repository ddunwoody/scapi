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

import java.math.BigInteger;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPrivateKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupOnByteArrayCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.tools.Factories.KdfFactory;

public class ScCramerShoupDDHOnByteArray extends CramerShoupAbs{

	private KeyDerivationFunction kdf;	// The underlying KDF to use in the encryption.
	
	/**
	 * Default constructor. It uses a default Dlog group and CryptographicHash.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnByteArray() {
		super();
		//Creates a default implementation of KDF.
		setKdf(new HKDF(new BcHMAC()));
	}

	private void setKdf(KeyDerivationFunction kdf){
		this.kdf = kdf;
	}
	
	/**
	 * Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.
	 * @param dlogGroup underlying DlogGroup to use.
	 * @param hash underlying hash to use.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnByteArray(DlogGroup dlogGroup, CryptographicHash hash, KeyDerivationFunction kdf){
		super(dlogGroup, hash);
		//Sets the given KDF.
		setKdf(kdf);
	}

	/**
	 * Constructor that lets the user choose the underlying dlog, hash and source of randomness.
	 * @param dlogGroup underlying DlogGroup to use.
	 * @param hash underlying hash to use.
	 * @param random source of randomness.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnByteArray(DlogGroup dlogGroup, CryptographicHash hash, KeyDerivationFunction kdf, SecureRandom random){
		super(dlogGroup, hash, random);
		//Sets the given KDF.
		setKdf(kdf);
	}

	/**
	 * Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.
	 * @param dlogGroupName name of the underlying dlog group
	 * @param hashName name of the underlying hash function
	 * @throws FactoriesException if one of the algorithm's names is not supported
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnByteArray(String dlogGroupName, String hashName, String kdfName) throws FactoriesException{
		super(dlogGroupName, hashName);
		//Sets the given KDF.
		setKdf(KdfFactory.getInstance().getObject(kdfName));
	}
	
	/**
	 * Constructor that lets the user choose the underlying dlog, hash and source of randomness.
	 * @param dlogGroupName name of the underlying dlog group.
	 * @param hashName name of the underlying hash function.
	 * @param randNumGenAlg random number generation algorithm.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnByteArray(String dlogGroupName, String hashName, String kdfName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		super(dlogGroupName, hashName, randNumGenAlg);
		//Sets the given KDF.
		setKdf(KdfFactory.getInstance().getObject(kdfName));
	}
	
	/**
	 * CramerShoup decrypt function can be optimized if, instead of using the x value in the private key as is, 
	 * we change it to be q-x, while q is the dlog group order.
	 * This function computes this changing and saves the new private value as the private key member.
	 * @param privateKey to change.
	 */
	protected void initPrivateKey(PrivateKey privateKey){
		//Sets the given key as is.
		this.privateKey = (CramerShoupPrivateKey) privateKey;
	}
	
	/**
	 * Cramer-Shoup on byte array encryption scheme has no limit of the byte array length to generate a plaintext from.
	 * @return false.  
	 */
	public boolean hasMaxByteArrayLengthForPlaintext(){
		return false;
	}
	
	/**
	 * CramerShoupDDHOnByteArray encryption can get any plaintext length.
	 * @throws NoMaxException.
	 */
	public int getMaxLengthOfByteArrayForPlaintext(){
		throw new NoMaxException("CramerShoupDDHOnByteArray encryption can get any plaintext length");
	}
	
	/**
	 * Generates a Plaintext suitable to CramerShoup encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 */
	public Plaintext generatePlaintext(byte[] text){
		
		return new ByteArrayPlaintext(text);
	}

	/**
	 * Encrypts the given plaintext using this Cramer Shoup encryption scheme.
	 * @param plaintext message to encrypt. MUST be an instance of ByteArrayPlaintext.
	 * @return Ciphertext the encrypted plaintext.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext is not instance of ByteArrayPlaintext.
	 */
	@Override
	public AsymmetricCiphertext encrypt(Plaintext plaintext){
		/*
		 * 	Choose a random  r in Zq<p>
		 *	Calculate 	u1 = g1^r<p>
		 *         		u2 = g2^r<p>
		 *         		e = (h^r)*msgEl<p>
		 *	Convert u1, u2, e to byte[] using the dlogGroup<P>
		 *	Compute alpha  - the result of computing the hash function on the concatenation u1+ u2+ e.<>
		 *	Calculate v = c^r * d^(r*alpha)<p>
		 *	Create and return an CramerShoupCiphertext object with u1, u2, e and v.
		 */
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of ByteArrayPlaintext");
		}
		byte[] msg = ((ByteArrayPlaintext) plaintext).getText();
		
		BigInteger r = chooseRandomR();
		GroupElement u1 = calcU1(r);
		GroupElement u2 = calcU2(r);
		GroupElement hExpr = calcHExpR(r);
		byte[] hrBytes = dlogGroup.mapAnyGroupElementToByteArray(hExpr);
		byte[] e = kdf.derivateKey(hrBytes, 0, hrBytes.length, msg.length).getEncoded();
		
		//Xores the result from the kdf with the plaintext.
		for(int i=0; i<msg.length; i++){
			e[i] = (byte) (e[i] ^ msg[i]);
		}
				
		byte[] u1ToByteArray = dlogGroup.mapAnyGroupElementToByteArray(u1);
		byte[] u2ToByteArray = dlogGroup.mapAnyGroupElementToByteArray(u2);
		
		//Calculates the hash(u1 + u2 + e).
		byte[] alpha = calcAlpha(u1ToByteArray, u2ToByteArray, e);
		
		//Calculates v = c^r * d^(r*alpha).
		GroupElement v = calcV(r, alpha); 
		
		//Creates and return an CramerShoupCiphertext object with u1, u2, e and v.
		return new CramerShoupOnByteArrayCiphertext(u1, u2, e, v);
	}
	
	/**
	 * Decrypts the given ciphertext using this Cramer-Shoup encryption scheme.
	 * @param ciphertext ciphertext to decrypt. MUST be an instance of CramerShoupOnByteArrayCiphertext.
	 * @return Plaintext the decrypted cipher.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given Ciphertext is not instance of CramerShoupOnByteArrayCiphertext.
	 */
	@Override
	public Plaintext decrypt(AsymmetricCiphertext ciphertext) throws KeyException{
		/*
			If cipher is not instance of CramerShoupOnByteArrayCiphertext, throw IllegalArgumentException.
			If private key is null, then cannot decrypt. Throw exception. 
			Convert u1, u2 to byte[] using the dlogGroup
			Compute alpha - the result of computing the hash function on the concatenation u1+ u2+ e.
			if u_1^(x1+y1*alpha) * u_2^(x2+y2*alpha) != v throw exception
			Calculate m = KDF(u1^z) XOR e   
			m is a byte array. Use it to create and return an instance of ByteArrayPlaintext.
		 */
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be Cramer Shoup ciphertext.
		if (!(ciphertext instanceof CramerShoupOnByteArrayCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of CramerShoupOnByteArrayCiphertext");
		}
		CramerShoupOnByteArrayCiphertext cipher = (CramerShoupOnByteArrayCiphertext) ciphertext;
		
		//Converts the u1, u2 and e elements to byte[].
		byte[] u1 = dlogGroup.mapAnyGroupElementToByteArray(cipher.getU1());
		byte[] u2 = dlogGroup.mapAnyGroupElementToByteArray(cipher.getU2());
		byte[] e = cipher.getE();
		
		//Calculates the hash(u1 + u2 + e).
		byte[] alpha = calcAlpha(u1, u2, e);

		checkValidity(cipher, alpha);
		
		//Calculates m = KDF((u1^z) XOR e. 
		GroupElement u1ExpZ = dlogGroup.exponentiate(cipher.getU1(), privateKey.getPrivateExp5());
		byte[] u1ExpZBytes = dlogGroup.mapAnyGroupElementToByteArray(u1ExpZ);
		byte[] m = kdf.derivateKey(u1ExpZBytes, 0, u1ExpZBytes.length, e.length).getEncoded();
		
		//Xores the result from the kdf with the plaintext.
		for(int i=0; i<e.length; i++){
			m[i] = (byte) (m[i] ^ e[i]);
		}
		
		//Creates a plaintext object with the group element and return it.
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