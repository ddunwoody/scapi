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
package edu.biu.scapi.tools.Provider.Hash;

import java.security.MessageDigest;

import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.bc.BcSHA1;
import edu.biu.scapi.primitives.hash.bc.BcSHA224;
import edu.biu.scapi.primitives.hash.bc.BcSHA256;
import edu.biu.scapi.primitives.hash.bc.BcSHA384;
import edu.biu.scapi.primitives.hash.bc.BcSHA512;

/** 
 * 
 * @author LabTest
 *
 */
public abstract class MessageDigestProvider extends MessageDigest {
	
	private CryptographicHash crHash;//the underlying collision resistant hash

	/** 
	 * 
	 */
	public void engineReset() {
			}

	/** 
	 * 
	 */
	public int engineGetDigestLength() {
		
		return crHash.getHashedMsgSize();
	}

	/**
	 * 
	 */
	public byte[] engineDigest() {

		byte[] out = new byte[crHash.getHashedMsgSize()];
		
		crHash.hashFinal(out, 0);
		
		return out;
		
	}

	/**
	 * 
	 */
	public void engineUpdate(byte[] in, int inOffset, int inLen) {
		
		crHash.update(in, inOffset, inLen);
		
	}
	
	public void engineUpdate(byte in) {
		
		byte[] inputArray = new byte[1];
		
		inputArray[0] = in;

		crHash.update(inputArray, 0, inputArray.length);
		
	}

	/**
	 * 
	 * @param crHash
	 */
	public MessageDigestProvider(CryptographicHash crHash) {
		
		super(crHash.getAlgorithmName());
		this.crHash = crHash;
		
	}
	
	static public class SHA1 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA1() {
			super(new BcSHA1());
			// TODO Auto-generated constructor stub
		}
	}

	static public class SHA224 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA224() {
			super(new BcSHA224());
			// TODO Auto-generated constructor stub
		}
	
	}
	
	static public class SHA256 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA256() {
			super(new BcSHA256());
			// TODO Auto-generated constructor stub
		}
	
	}
	
	static public class SHA384 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA384() {
			super(new BcSHA384());
			// TODO Auto-generated constructor stub
		}
	
	}
	
	static public class SHA512 extends MessageDigestProvider{

		/**
		 * 
		 */
		public SHA512() {
			super(new BcSHA512());
			// TODO Auto-generated constructor stub
		}
	
	}
}
