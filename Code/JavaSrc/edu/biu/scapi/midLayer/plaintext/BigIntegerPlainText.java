package edu.biu.scapi.midLayer.plaintext;

import java.math.BigInteger;

/**
 * This class holds the plaintext as a BigInteger.
 * 
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
	
	@Override
	public boolean equals(Object plaintext){
		if (!(plaintext instanceof BigIntegerPlainText)){
			return false;
		}
		BigInteger x1 = ((BigIntegerPlainText) plaintext).getX();
		
		if (!x.equals(x1)){
			return false;
		} 
		
		return true;
	}
	
}
