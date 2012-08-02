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
/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCramerShoupPublicKey implements CramerShoupPublicKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = -5021534858851154694L;
	
	private GroupElement c;
	private GroupElement d;
	private GroupElement h;
	private GroupElement g1;
	private GroupElement g2;

	
	public ScCramerShoupPublicKey(GroupElement c, GroupElement d, GroupElement h, GroupElement g1, GroupElement g2) {
		super();
		this.c = c;
		this.d = d;
		this.h = h;
		this.g1 = g1;
		this.g2 = g2;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return "CramerShoup";	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		return null;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return null;
	}
	
	public GroupElement getC() {
		return c;
	}

	public GroupElement getD() {
		return d;
	}

	public GroupElement getH() {
		return h;
	}
	
	public GroupElement getGenerator1(){
		return g1;
	}

	public GroupElement getGenerator2(){
		return g2;
	}
}
