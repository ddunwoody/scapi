package edu.biu.scapi.midLayer.symmetricCrypto.keys;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is a container for the data needed to generate a key for Symmetric Encryption.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class SymKeyGenParameterSpec implements AlgorithmParameterSpec {

		private int encKeySize;
		
		/**
		 * 
		 * This Parameter Spec holds the key size of the Secret Key we want to generate.
		 * @param encKeySize an int indicating the size of the secret key
		 * 
		 */
		public SymKeyGenParameterSpec(int encKeySize){
			this.encKeySize = encKeySize;
		}
		
		/**
		 * This function returns the size of the secret key we want to generate. It is generally used to pass the size to some key generator.
		 * @return The size of the key to generate.
		 */
		public int getEncKeySize() {
			return encKeySize;
		}
}
