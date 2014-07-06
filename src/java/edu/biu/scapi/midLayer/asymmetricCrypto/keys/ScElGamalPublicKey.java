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


package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScCramerShoupPublicKey.ScCramerShoupPublicKeySendableData;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * This class represents a Public Key suitable for the El Gamal Encryption Scheme. Although the constructor is public, it should only be instantiated by the 
 * Encryption Scheme itself via the generateKey function. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScElGamalPublicKey implements ElGamalPublicKey {

	private static final long serialVersionUID = 8645777933993577969L;
	private GroupElement h;
	
	public ScElGamalPublicKey(GroupElement h){
		this.h = h;
	}
	
	@Override
	public String getAlgorithm() {
		
		return "ElGamal";
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}
	
	public GroupElement getH(){
		return h;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPublicKey#generateSendableData()
	 */
	@Override
	public KeySendableData generateSendableData() {
		return new ScElGamalPublicKeySendableData(h.generateSendableData());
	}
	
	
	static public class ScElGamalPublicKeySendableData implements KeySendableData {
			private static final long serialVersionUID = 334589064982559017L;
		private GroupElementSendableData c;

		public ScElGamalPublicKeySendableData(GroupElementSendableData c) {
			super();
			this.c = c;
		}

		public GroupElementSendableData getC() {
			return c;
		}
		
		
	}

}
