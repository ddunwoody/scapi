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
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class ScCramerShoupPrivateKeySpec implements KeySpec {
	private BigInteger x1;
	private BigInteger x2;
	private BigInteger y1;
	private BigInteger y2;
	private BigInteger z;
	
	public ScCramerShoupPrivateKeySpec(BigInteger x1, BigInteger x2,
			BigInteger y1, BigInteger y2, BigInteger z) {
		super();
		this.x1 = x1;
		this.x2 = x2;
		this.y1 = y1;
		this.y2 = y2;
		this.z = z;
	}
	public BigInteger getX1() {
		return x1;
	}
	public BigInteger getX2() {
		return x2;
	}
	public BigInteger getY1() {
		return y1;
	}
	public BigInteger getY2() {
		return y2;
	}
	public BigInteger getZ() {
		return z;
	}
	
	
}
