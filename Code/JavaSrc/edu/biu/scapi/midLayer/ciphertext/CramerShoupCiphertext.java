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
package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;

public abstract class CramerShoupCiphertext implements AsymmetricCiphertext{

	private GroupElement u1;
	private GroupElement u2;
	private GroupElement v;
	
	public CramerShoupCiphertext(GroupElement u1, GroupElement u2, GroupElement v) {
		this.u1 = u1;
		this.u2 = u2;
		this.v = v;
	}

	public GroupElement getU1() {
		return u1;
	}

	public GroupElement getU2() {
		return u2;
	}

	public GroupElement getV() {
		return v;
	}
}
