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
package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * KeyFactory for Rabin keys. Translates Rabin keys to RabinKeySpec and vice versa.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScRabinKeyFactory extends KeyFactorySpi{

	/**
	 * generates a ScRabinPrivateKey from the given keySpec.
	 * @param spec should be ScRabinPrivateKeySpec
	 * @throws InvalidKeySpecException if the gives KeySpec is not an instance of ScRabinPrivateKeySpec
	 */
	public PrivateKey engineGeneratePrivate(KeySpec spec)
			throws InvalidKeySpecException {
	//NOTE - we changed the access member modifier of this function from protected to public
		//checks that the keySpec is of type ScRabinPrivateKeySpec
		if (spec instanceof ScRabinPrivateKeySpec){
			//extracts the rabin private key parameters
			ScRabinPrivateKeySpec privateKeySpec = (ScRabinPrivateKeySpec)spec;
			BigInteger mod = privateKeySpec.getModulus();
			BigInteger p = privateKeySpec.getPrime1();
			BigInteger q = privateKeySpec.getPrime2();
			BigInteger u = privateKeySpec.getInversePModQ();
			//creates new ScRabinPrivateKey with the parameters given in the keySpec
			return new ScRabinPrivateKey(mod, p, q, u);
		}
		//if the given keySpec is not a ScRabinPrivateKeySpec throws exception
		throw new InvalidKeySpecException("KeySpec must be ScRabinPrivateKeySpec");
	}
	
	/**
	 * generates a ScRabinPubliceKey from the given keySpec.
	 * @param spec should be ScRabinPublicKeySpec
	 * @throws InvalidKeySpecException if the gives KeySpec is not an instance of ScRabinPublicKeySpec
	 */
	public PublicKey engineGeneratePublic(KeySpec spec)
			throws InvalidKeySpecException {
	//NOTE - we changed the access member modifier of this function from protected to public
		//checks that the keySpec is of type ScRabinPublicKeySpec
		if (spec instanceof ScRabinPublicKeySpec){
			//extracts the rabin public key parameters
			ScRabinPublicKeySpec publicKeySpec = (ScRabinPublicKeySpec)spec;
			BigInteger mod = publicKeySpec.getModulus();
			BigInteger r = publicKeySpec.getQuadraticResidueModPrime1();
			BigInteger s = publicKeySpec.getQuadraticResidueModPrime2();
			//creates new ScRabinPublicKey with the parameters given in the keySpec
			return new ScRabinPublicKey(mod, r, s);
		}
		//if the given keySpec is not a ScRabinPublicKeySpec throws exception
		throw new InvalidKeySpecException("KeySpec must be ScRabinPublicKeySpec");
	}

	/**
	 * Returns the KeySpec corresponding to the given key.
	 * The returned KeySpec will be of type T, if that is a valid KeySpec for the given key
	 * @throws InvalidKeySpecException if keyDpec is not a valid KeySpec for the given key
	 * or if the given key is not a valid rabin key
	 */
	public <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
			throws InvalidKeySpecException {
	//NOTE - we changed the access member modifier of this function from protected to public
		//converts the given key to SCAPI key
		try {
			key = engineTranslateKey(key);
		//if the key is not a valid rabin key, throw exception
		} catch (InvalidKeyException e) {
			throw new InvalidKeySpecException(e);
		}
		
		if(key instanceof RabinPublicKey){
			if ((ScRabinPublicKeySpec.class).isAssignableFrom(keySpec)) {
				//if the given key is a RabinPublicKey and the given keySpec is 
				//ScRabinPublicKeySpec class, get the key parameters and creates a ScRabinPublicKeySpec
				RabinPublicKey publicKey = (RabinPublicKey)key;
				BigInteger mod = publicKey.getModulus();
				BigInteger r = publicKey.getQuadraticResidueModPrime1();
				BigInteger s = publicKey.getQuadraticResidueModPrime2();
				return (T) new ScRabinPublicKeySpec(mod, r, s);
			}
			//if the keySpec is not a ScRabinPublicKeySpec class, throws exception
			throw new InvalidKeySpecException ("KeySpec must be ScRabinPublicKeySpec");
        }
		if (key instanceof RabinPrivateKey){
			if ((ScRabinPrivateKeySpec.class).isAssignableFrom(keySpec)) {
				//if the given key is a RabinPrivateKey and the given keySpec is 
				//ScRabinPrivateKeySpec class, get the key parameters and creates a ScRabinPrivateKeySpec
				RabinPrivateKey publicKey = (RabinPrivateKey)key;
				BigInteger mod = publicKey.getModulus();
				BigInteger p = publicKey.getPrime1();
				BigInteger q = publicKey.getPrime2();
				BigInteger u = publicKey.getInversePModQ();
				return (T) new ScRabinPrivateKey(mod, p, q, u);
			}
			//if the keySpec is not a ScRabinPrivateKeySpec class, throws exception
			throw new InvalidKeySpecException ("KeySpec must be ScRabinPrivateKeySpec");
		}
		//if the key is not public or private key, throws exception
		throw new InvalidKeySpecException("Key must be RabinPublicKey or RabinPrivateKey");
	}

	/**
	 * Translate RabinKey to SCAPI key
	 */
	public Key engineTranslateKey(Key key) throws InvalidKeyException {
	//NOTE - we changed the access member modifier of this function from protected to public
		if(key == null){
			throw new InvalidKeyException("Key must not be null");
		}
		//if the key is not rabin key - throws exception
		if (key.getAlgorithm() != "Rabin"){
			throw new InvalidKeyException("Key must be instance of Rabin key");
		}
		//key is RabinPublicKey - creates a ScRabinPublicKey
		if (key instanceof RabinPublicKey){
			if(key instanceof ScRabinPublicKey){
				return key;
			}
			RabinPublicKey publicKey = (RabinPublicKey)key;
			BigInteger mod = publicKey.getModulus();
			BigInteger r = publicKey.getQuadraticResidueModPrime1();
			BigInteger s = publicKey.getQuadraticResidueModPrime2();
			return new ScRabinPublicKey(mod, r, s);
		}
		//key is RabinPrivateKey - creates a ScRabinPrivateKey
		if (key instanceof RabinPrivateKey){
			if(key instanceof ScRabinPrivateKey){
				return key;
			}
			RabinPrivateKey publicKey = (RabinPrivateKey)key;
			BigInteger mod = publicKey.getModulus();
			BigInteger p = publicKey.getPrime1();
			BigInteger q = publicKey.getPrime2();
			BigInteger u = publicKey.getInversePModQ();
			return new ScRabinPrivateKey(mod, p, q, u);
		}
		//if the key is not public or private - throws exception
		throw new InvalidKeyException("key must be RabinPublicKey or RabinPrivateKey");
	}

}
