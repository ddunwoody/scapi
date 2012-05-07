/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.security.spec.AlgorithmParameterSpec;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class AsymKeyGenParameterSpec implements AlgorithmParameterSpec {
	private int privateKeySize;
	private int publicKeySize;
	public AsymKeyGenParameterSpec(int privateKeySize, int publicKeySize) {
		super();
		this.privateKeySize = privateKeySize;
		this.publicKeySize = publicKeySize;
	}
	public int getPrivateKeySize() {
		return privateKeySize;
	}
	public int getPublicKeySize() {
		return publicKeySize;
	}
	

}
