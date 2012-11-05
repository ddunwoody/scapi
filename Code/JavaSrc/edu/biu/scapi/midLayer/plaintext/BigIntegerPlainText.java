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
package edu.biu.scapi.midLayer.plaintext;

import java.io.Serializable;
import java.math.BigInteger;

import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;

/**
 * This class holds the plaintext as a BigInteger.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class BigIntegerPlainText implements Plaintext, PlaintextSendableData {
	/**
	 * 
	 */
	private static final long serialVersionUID = -6018721600601611396L;
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
	
	/**
	 * @see edu.biu.scapi.midLayer.plaintext.Plaintext#generateSendableData()
	 */
	@Override
	public PlaintextSendableData generateSendableData() {
		//Since BigIntegerPlainText is both a Plaintext and a PlaintextSendableData, on the one hand it has to implement
		//the generateSendableData() function, but on the other hand it is in itself an PlaintextSendableData, so we do not really
		//generate sendable data, but just return this object.
		return this;
	}
}
