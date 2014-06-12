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

import java.security.InvalidKeyException;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.exceptions.CiphertextTooLongException;

/**
 * An interface that {@link StandardGarbledGate}'s and any specialized or optimized garbled gate will implement. <p>
 * This will allow the correct method to be caused in cases in which we are dealing with different types of optimized Gates. <p>
 * For example, say that we are using the Free-XOR technique. In this case, we will have a mixture of {@link StandardGarbledGate}s and
 * {@link FreeXORGate}s. We will use this interface so that we can access both of them without knowing ahead of time which one we will be given.
 * 
 * @author Steven Goldfeder
 * 
 */
public interface GarbledGate {
  	
	/**
	 * Computes the output of this gate and sets the output wire(s) to that value.
	 * @param computedWires A {@link Map} containing the {@link GarbledWires}s that have already been computed and had their values set.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws CiphertextTooLongException
	 */
	public void compute(Map<Integer, GarbledWire> computedWires) throws InvalidKeyException, IllegalBlockSizeException, CiphertextTooLongException;

	/**
	 * This method tests an ungarbled {@link Gate} for equality to this {@code GarbledGate}. <P>
	 * That is, they have the same truth table and indices.<p>
	 * It is called verify since in general, when this method is used, the assumption is that they are equal and we are verifying this assumption.
	 * @param g an ungarbled {@code Gate} to be tested for equality to this {@code GarbledGate}.
	 * @param allWireValues contains both keys of all wires.
	 * @return {@code true} if the gates have the same truth table and indeces, and {@code false} otherwise.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws CiphertextTooLongException
	 */
	boolean verify(Gate g, Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException, IllegalBlockSizeException, CiphertextTooLongException;

	/**
	 * @return an array containing the indices of the gate's input wires.
	 */
	public int[] getInputWireIndices();

	/**
	 * @return an array containing the indices of the gate's output wires.
	 * Generally this will be a single wire, but if fan-out >1 a circuit designer may index it as multiple wires.
	 */
	public int[] getOutputWireIndices();
  
}
