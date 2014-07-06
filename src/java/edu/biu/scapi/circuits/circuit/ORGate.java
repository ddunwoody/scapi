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

import java.util.BitSet;

/**
 * A built in OR Gate for the convenience of circuit designers. <p>
 * This gate is identical to creating a {@link Gate} with a 0111 truth table.
 * 
 * @author Steven Goldfeder
 */

public class ORGate extends Gate {

	/**
	 * Constructs an OR Gate.
	 * 
	 * @param gateNumber The gate's number (in a circuit all gates will be numbered).
	 * @param inputWireIndices An array containing the indices of the gate's input {@code Wire}s.
	 * @param outputWireIndices An array containing the indices of the gate's input {@code Wire}(s). 
	 * There will generally be a single output {@code Wire}. However in instances in which the fan-out of the output {@code Wire} is >1, 
	 * we left the option for treating this as multiple {@code Wire}s.
	 */
	public ORGate(int gateNumber, int[] inputWireIndices, int[] outputWireIndices) {
		super(gateNumber, createORTruthTable(), inputWireIndices, outputWireIndices);
	}

	/**
	 * 
	 * @return a {@link BitSet} representation of an OR Gate truth table to be passed to the super constructor.
	 */
	private static BitSet createORTruthTable() {
	    BitSet truthTable = new BitSet();
	    truthTable.set(1);
	    truthTable.set(2);
	    truthTable.set(3);
	    return truthTable;
	}

}
