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
package edu.biu.scapi.circuits.garbledCircuit;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

/**
 * A class that holds the values used to create the circuit using a pseudo random generator and a seed. <p>
 * These values are:<p>
 * 1. Both keys of the input and the output wires.<p>
 * 2. The output wire's values.<p>
 * 3. The signal bits of the input wires. They are returned in order to enable generating keys out of the input wires' keys.<p>
 * 4. The result of applying a hash function on the circuit's garbled tables.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CircuitSeedCreationValues extends CircuitCreationValues{

	byte[] hashedTables;
	
	/**
	 * Sets the given arguments.
	 * @param allInputWireValues Both keys for all input wires.
	 * @param allOutputWireValues Both keys for all output wires.
	 * @param outputWireValues Signal bits of all output wires.
	 * @param hashedTables The result of the hash function of the garbled tables.
	 */
	public CircuitSeedCreationValues(Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, SecretKey[]> allOutputWireValues, 
			HashMap<Integer, Byte> outputWireValues, byte[] hashedTables){
		super(allInputWireValues, allOutputWireValues, outputWireValues);
		this.hashedTables = hashedTables;
	}
	
	public byte[] getHashedTables(){
		return hashedTables;
	}
}
