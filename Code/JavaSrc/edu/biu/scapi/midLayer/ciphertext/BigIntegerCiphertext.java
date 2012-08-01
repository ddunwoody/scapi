package edu.biu.scapi.midLayer.ciphertext;

import java.math.BigInteger;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class BigIntegerCiphertext implements AsymmetricCiphertext {
	private BigInteger cipher;

	public BigIntegerCiphertext(BigInteger cipher) {
		super();
		this.cipher = cipher;
	}

	public BigInteger getCipher() {
		return cipher;
	}
	
}
