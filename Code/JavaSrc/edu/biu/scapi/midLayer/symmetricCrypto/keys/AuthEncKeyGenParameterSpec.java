package edu.biu.scapi.midLayer.symmetricCrypto.keys;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is a container for the data needed to generate a key for Authenticated Encryption.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class AuthEncKeyGenParameterSpec implements AlgorithmParameterSpec {

		private int encKeySize;
		private int macKeySize;
		
		public AuthEncKeyGenParameterSpec(int encKeySize, int macKeySize){
			this.encKeySize = encKeySize;
			this.macKeySize = macKeySize;
		}
		
		public int getEncKeySize() {
			return encKeySize;
		}
		
		public int getMacKeySize() {
			return macKeySize;
		}
}
