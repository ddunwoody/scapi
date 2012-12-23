/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
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
