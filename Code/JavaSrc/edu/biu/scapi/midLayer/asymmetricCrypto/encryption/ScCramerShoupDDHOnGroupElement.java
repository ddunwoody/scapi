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
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.*;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupOnGroupElementCiphertext;
import edu.biu.scapi.midLayer.plaintext.GroupElementPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.*;
import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
 * Concrete class that implement Cramer-Shoup encryption scheme.
 * By definition, this encryption scheme is CCA-secure and NonMalleable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCramerShoupDDHOnGroupElement extends CramerShoupAbs {
	
	/**
	 * Default constructor. It uses a default Dlog group and CryptographicHash.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnGroupElement() {
		super();
	}

	/**
	 * Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.
	 * @param dlogGroup underlying DlogGroup to use.
	 * @param hash underlying hash to use.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnGroupElement(DlogGroup dlogGroup, CryptographicHash hash){
		super(dlogGroup, hash);
	}

	/**
	 * Constructor that lets the user choose the underlying dlog, hash and source of randomness.
	 * @param dlogGroup underlying DlogGroup to use.
	 * @param hash underlying hash to use.
	 * @param random source of randomness.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnGroupElement(DlogGroup dlogGroup, CryptographicHash hash, SecureRandom random){
		super(dlogGroup, hash, random);
	}

	/**
	 * Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.
	 * @param dlogGroupName name of the underlying dlog group
	 * @param hashName name of the underlying hash function
	 * @throws FactoriesException if one of the algorithm's names is not supported
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnGroupElement(String dlogGroupName, String hashName) throws FactoriesException{
		super(dlogGroupName, hashName);
	}
	
	/**
	 * Constructor that lets the user choose the underlying dlog, hash and source of randomness.
	 * @param dlogGroupName name of the underlying dlog group.
	 * @param hashName name of the underlying hash function.
	 * @param randNumGenAlg random number generation algorithm.
	 * @throws IllegalArgumentException if the given dlog group does not have DDH security level.
	 */
	public ScCramerShoupDDHOnGroupElement(String dlogGroupName, String hashName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException{
		super(dlogGroupName, hashName, randNumGenAlg);
	}
	
	/**
	 * CramerShoup decrypt function can be optimized if, instead of using the x value in the private key as is, 
	 * we change it to be q-x, while q is the dlog group order.
	 * This function computes this changing and saves the new private value as the private key member.
	 * @param privateKey to change.
	 */
	protected void initPrivateKey(PrivateKey privateKey){
		CramerShoupPrivateKey key = (CramerShoupPrivateKey) privateKey;
		//Gets the z value from the private key.
		BigInteger z = key.getPrivateExp5();
		//Gets the q-z value.
		BigInteger xInv = dlogGroup.getOrder().subtract(z);
		//Sets the q-z value as the z in private key.
		this.privateKey = new ScCramerShoupPrivateKey(key.getPrivateExp1(), key.getPrivateExp2(), key.getPrivateExp3(), key.getPrivateExp4(), xInv);
	}
	
	/**
	 * Cramer-Shoup on GroupElement encryption scheme has a limit of the byte array length to generate a plaintext from.
	 * @return true. 
	 */
	public boolean hasMaxByteArrayLengthForPlaintext(){
		return true;
	}
	
	/**
	 * Returns the maximum size of the byte array that can be passed to generatePlaintext function. 
	 * This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	 * @return the maximum size of the byte array that can be passed to generatePlaintext function. 
	 */
	public int getMaxLengthOfByteArrayForPlaintext(){
		return dlogGroup.getMaxLengthOfByteArrayForEncoding();
	}
	
	/**
	 * Generates a Plaintext suitable to CramerShoup encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 * @throws IllegalArgumentException if the given message's length is greater than the maximum. 
	 */
	public Plaintext generatePlaintext(byte[] text){
		if (text.length > getMaxLengthOfByteArrayForPlaintext()){
			throw new IllegalArgumentException("the given text is too big for plaintext");
		}
		
		return new GroupElementPlaintext(dlogGroup.encodeByteArrayToGroupElement(text));
	}

	/**
	 * Encrypts the given plaintext using this Cramer Shoup encryption scheme.
	 * @param plaintext message to encrypt. MUST be an instance of GroupElementPlaintext.
	 * @return Ciphertext the encrypted plaintext.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext is not instance of GroupElementPlaintext.
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
		if (!(plaintext instanceof GroupElementPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of GroupElementPlaintext");
		}
		GroupElement msgElement = ((GroupElementPlaintext) plaintext).getElement();
		
		BigInteger r = chooseRandomR();
		GroupElement u1 = calcU1(r);
		GroupElement u2 = calcU2(r);
		GroupElement hExpr = calcHExpR(r);
		GroupElement e = dlogGroup.multiplyGroupElements(hExpr, msgElement);
		
		byte[] u1ToByteArray = dlogGroup.mapAnyGroupElementToByteArray(u1);
		byte[] u2ToByteArray = dlogGroup.mapAnyGroupElementToByteArray(u2);
		byte[] eToByteArray = dlogGroup.mapAnyGroupElementToByteArray(e);
		
		//Calculates the hash(u1 + u2 + e).
		byte[] alpha = calcAlpha(u1ToByteArray, u2ToByteArray, eToByteArray);
		
		//Calculates v = c^r * d^(r*alpha).
		GroupElement v = calcV(r, alpha); 
		
		//Creates and return an CramerShoupCiphertext object with u1, u2, e and v.
		CramerShoupOnGroupElementCiphertext cipher = new CramerShoupOnGroupElementCiphertext(u1, u2, e, v);
		return cipher;
	}
	
	
	/**
	 * Decrypts the given ciphertext using this Cramer-Shoup encryption scheme.
	 * @param ciphertext ciphertext to decrypt. MUST be an instance of CramerShoupCiphertext.
	 * @return Plaintext the decrypted cipher.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given Ciphertext is not instance of CramerShoupCiphertext.
	 */
	@Override
	public Plaintext decrypt(AsymmetricCiphertext ciphertext) throws KeyException{
		/*
			If cipher is not instance of CramerShoupCiphertext, throw IllegalArgumentException.
			If private key is null, then cannot decrypt. Throw exception. 
			Convert u1, u2, e to byte[] using the dlogGroup
			Compute alpha - the result of computing the hash function on the concatenation u1+ u2+ e.
			if u_1^(x1+y1*alpha) * u_2^(x2+y2*alpha) != v throw exception
			Calculate m = e*((u1^z)^-1)   // equal to m = e/u1^z . We don’t have a divide operation in DlogGroup so we calculate it in equivalent way
			m is a groupElement. Use it to create and return msg an instance of GroupElementPlaintext.
			return msg
		 */
		//If there is no private key, throws exception.
		if (privateKey == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Ciphertext should be Cramer Shoup ciphertext.
		if (!(ciphertext instanceof CramerShoupOnGroupElementCiphertext)){
			throw new IllegalArgumentException("ciphertext should be instance of CramerShoupCiphertext");
		}
		Plaintext plaintext = null;

		CramerShoupOnGroupElementCiphertext cipher = (CramerShoupOnGroupElementCiphertext) ciphertext;
		
		//Converts the u1, u2 and e elements to byte[].
		byte[] u1 = dlogGroup.mapAnyGroupElementToByteArray(cipher.getU1());
		byte[] u2 = dlogGroup.mapAnyGroupElementToByteArray(cipher.getU2());
		byte[] e = dlogGroup.mapAnyGroupElementToByteArray(cipher.getE());
		
		//Calculates the hash(u1 + u2 + e).
		byte[] alpha = calcAlpha(u1, u2, e);

		checkValidity(cipher, alpha);
		
		//Calculates m = e*((u1^z)^ -1). 
		//Instead of calculating (u1^z)^-1, we use the optimization that was calculated in initPrivateKey function and calculate u1^zInv.
		GroupElement U1ExpInvZ = dlogGroup.exponentiate(cipher.getU1(), privateKey.getPrivateExp5());
		GroupElement m = dlogGroup.multiplyGroupElements(cipher.getE(), U1ExpInvZ);
		
		//Creates a plaintext object with the group element and return it.
		plaintext = new GroupElementPlaintext(m);
		
		return plaintext;
	}
	
	/**
	 * Generates a byte array from the given plaintext. 
	 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has, 
	 * and therefore he is working on byte array.
	 * @param plaintext to generates byte array from. MUST be an instance of GroupElementPlaintext.
	 * @return the byte array generated from the given plaintext.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of GroupElementPlaintext.
	 */
	public byte[] generateBytesFromPlaintext(Plaintext plaintext){
		if (!(plaintext instanceof GroupElementPlaintext)){
			throw new IllegalArgumentException("plaintext should be an instance of GroupElementPlaintext");
		}
		GroupElement el = ((GroupElementPlaintext) plaintext).getElement();
		return dlogGroup.decodeGroupElementToByteArray(el);
	}
	
}
