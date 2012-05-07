/**
 * 
 */
package edu.biu.scapi.midLayer.plaintext;

import java.math.BigInteger;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class BigIntegerPlainText implements Plaintext {
	private BigInteger x;

	public BigInteger getX() {
		return x;
	}

	public BigIntegerPlainText(BigInteger x) {
		super();
		this.x = x;
	}
	
	public BigIntegerPlainText(String s) {
		super();
		this.x = new BigInteger(s.getBytes());
	}
	
}
