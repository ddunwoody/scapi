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
package edu.biu.scapi.circuits.circuit;

/**
 * The {@code Wire} class is a software representation of a {@code Wire} in a circuit. <p>
 * As these are {@code Wire}s for Boolean circuit's, each {@code Wire} can be set to either 0 or 1.
 * 
 * @author Steven Goldfeder
 * 
 */
public class Wire {

	/**
	 * The value that this wire carries. It can be set to either 0 or 1
  	 */
	private byte value;

	/**
	 * Creates a {@code Wire} and sets it to the specified value.
	 * 
	 * @param value The value to set this {@code Wire} to. Must be either 0 or 1.
  	 */
	public Wire(byte value) {
		// Ensures that the Wire is only set to a legal value (i.e. 0 or 1)
		if (value < 0 || value > 1) {
			  throw new IllegalArgumentException("Wire value can only be 0 or 1");
		} else {
			this.value = value;
		}
	}

	/**
	 * 
	 * @return the value (0 or 1) that this {@code Wire} is set to.
	 */
	public byte getValue() {
		return value;
	}
}
