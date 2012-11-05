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

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCramerShoupPublicKeySendableData implements KeySendableData {


	private static final long serialVersionUID = 5602965604695530544L;
	
	private GroupElementSendableData c;
	private GroupElementSendableData d;
	private GroupElementSendableData h;
	private GroupElementSendableData g1;
	private GroupElementSendableData g2;
	
	
	public ScCramerShoupPublicKeySendableData(GroupElementSendableData c,
			GroupElementSendableData d, GroupElementSendableData h,
			GroupElementSendableData g1, GroupElementSendableData g2) {
		super();
		this.c = c;
		this.d = d;
		this.h = h;
		this.g1 = g1;
		this.g2 = g2;
	}


	public GroupElementSendableData getC() {
		return c;
	}


	public GroupElementSendableData getD() {
		return d;
	}


	public GroupElementSendableData getH() {
		return h;
	}


	public GroupElementSendableData getG1() {
		return g1;
	}


	public GroupElementSendableData getG2() {
		return g2;
	}
	
}
