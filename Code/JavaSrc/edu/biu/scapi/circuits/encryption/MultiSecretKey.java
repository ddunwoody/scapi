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


package edu.biu.scapi.circuits.encryption;

import java.io.Serializable;

import javax.crypto.SecretKey;

/**
 * This class is the Key to be used when encrypting with any @link MultiKeyEncryption} scheme. <P>
 * It generalizes the notion of a dual key cipher that is generally associated with Yao's protocol. <p>
 * A dual key cipher uses two keys and is thus only appropriate for encrypting 2-input {@code GarbledGate}s. <p>
 * A MultiKey cipher can be used for any number of inputs. When it is used to encrypt a 2-input {@code GarbledGate}, it is a dual key 
 * cipher {@link MultiKeyEncryptionScheme}. <p>
 * It contains an array of {@link SecretKey}s that the {@link MultiKeyEncryptionScheme} will use to encrypt.
 * 
 * @author Steven Goldfeder
 * 
 */
public class MultiSecretKey implements Serializable{
  
	private static final long serialVersionUID = 1543950325054479100L;
	private SecretKey[] keys;

	/**
	 * A constructor that constructs a {@code MultiSecretKey} from any number of {@code SecretKey} objects. <P>
	 * The {@code SecretKey}s can be passed to the constructor either in an array or as separate parameters.
	 * 
	 * @param keys The {@code SecretKey}s that will be used to construct the {@code MultiSecretKey}. 
	 * The {@code SecretKey}s can be passed to the constructor either in an array or as separate parameters.
	 */
	 public MultiSecretKey(SecretKey... keys) {
		 this.keys = keys;
	 }

	 /**
	  * Returns an array of the {@code SecretKey}s from this {@code MultiSecretKey}.
	  * @return an array containing the individual {@code SecretKey} objects that make up this {@code MultiSecretKey}
	  */
	  public SecretKey[] getKeys() {
		  return keys;
	  }

	  /**
	   * @return the number of keys in this {@code MultiSecretKey}.
	   */
	  public int getNumberOfKeys() {
	    return keys.length;
	  }

}
