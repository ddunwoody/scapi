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
import java.util.Map;

/**
 * The {@code Gate} class is a software representation of a circuit's gate.<p>
 * It contains a truth table that performs a function on the values of the input {@code Wire}s and assigns 
 * that value to the output {@code Wire}(s).
 * 
 * @author Steven Goldfeder
 * 
 */

public class Gate {
  
	/**
	 * A BitSet representation of the final column of a truth table (i.e. the output of the function being computed).
	 */
	private BitSet truthTable;

	/**
	 * An array containing the indices of the input Wires of this gate. <P>
	 * The order of the {@code Wire}s in this array is significant as not all functions are symmetric.
	 */
	/*
	 * Note that the ordering of these Wires must be the same also since some functions are not symmetric. 
	 * For example consider the function ~y v x and the following truth table: 
	 * x       y    ~y v x 
	 * 0       0       1
	 * 0       1       0
	 * 1       0       1 
	 * 1       1       1
	 */
	private int[] inputWireIndices;
  
	/**
	 * An array containing the indices of the output {@code Wire}(s).
	 */
	private int[] outputWireIndices;
  
	/**
	 * The number of this {@code Gate}. This number is used to order {@code Gate}s in a {@link BooleanCircuit}.
	 */
	private int gateNumber;

	/**
	 * Sets the given values.
	 * @param gateNumber The gate's number (in a circuit all gates will be numbered).
	 * @param truthTable A BitSet representation of the final column of a truth table( i.e. the output of the function being computed).
	 * @param inputWireIndices An array containing the indices of the gate's input {@code Wire}s.
	 * @param outputWireIndices An array containing the indices of the gate's input {@code Wire}(s). 
	 * There will generally be a single output {@code Wire}. However in instances in which fan-out of the output {@code Wire} is >1, 
	 * we left the option for treating this as multiple {@code Wire}s.
	 */
	public Gate(int gateNumber, BitSet truthTable, int[] inputWireIndices, int[] outputWireIndices) {
	    this.gateNumber = gateNumber;
	    this.truthTable = truthTable;
	    this.inputWireIndices = inputWireIndices;
	    this.outputWireIndices = outputWireIndices;
	} 

	/**
	 * Compute the gate operation.<p>
	 * @param computedWires A {@code Map} that maps an integer wire index to the Wire. 
	 * The values of these {@code Wire}s has already been set (it has been <b>computed</b>--hence the name computedWires).
	 */
	void compute(Map<Integer, Wire> computedWires) {
    
		// We call the calculateIndexOfTruthTable method to tell us the position of the output value in the truth table 
		// and look up the value at that position.
		byte outputValue = (byte) ((truthTable.get(calculateIndexOfTruthTable(computedWires))) ? 1 : 0);

		int numberOfOutputs = outputWireIndices.length;
		// Assigns output value to each of this gate's output Wires.
		for (int i = 0; i < numberOfOutputs; i++) {
			computedWires.put(outputWireIndices[i], new Wire(outputValue));
		}
	}

	/**
	 * @param obj A gate that is to be tested for equality to the current {@code Gate}. 
	 * @return {@code true} if the gates are equivalent and {@code false} otherwise.
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Gate)){
			return false;
		}
		Gate g = (Gate) obj;
		
		// First we verify that the gates' numbers are the same.
		if (gateNumber != g.getGateNumber()) {
			return false;
		}
		
		// Next we verify that the gates' respective truth tables are the same.
		if (!truthTable.equals(g.truthTable)) {
			return false;
		}
		
		// Next we verify that the number of input and output wires to the two respective gates are equal.
		if ((inputWireIndices.length != g.inputWireIndices.length) || (outputWireIndices.length != g.outputWireIndices.length)) {
			return false;
		}
   
		/*
	     * Having determined that the number of input Wire's are the same, we now check that corresponding input wires 
	     * have the same index. As we demonstrated above (in the comments on the imputWireIndices field), the order of the 
	     * wires is significant as not all functions are symmetric. So not only do we care that Wire have the same indices, 
	     * but we also care that the wires with the same index are in the same position of the inputWireIndices array.
	     */
		int numberOfInputs = inputWireIndices.length;
		for (int i = 0; i < numberOfInputs; i++) {
			if (inputWireIndices[i] != g.inputWireIndices[i]) {
				return false;
			}
		}
		
		/*
		 * Having determined that the number of output Wire's are the same, we now check that corresponding output wires have 
		 * the same index.
		 */
		int numberOfOutputs = outputWireIndices.length;
		for (int i = 0; i < numberOfOutputs; i++) {
			if (outputWireIndices[i] != g.outputWireIndices[i]) {
				return false;
			}
		}
		
		// If we've reached this point, then the Gate's are equal so we return true.
		return true;
	}

	/**
	 * This is a helper method that calculates the index of the output value on a truth table corresponding to 
	 * the values of the input {@code Wire}s.
	 * 
	 * @param computedWires A {@code Map} that maps an integer wire index to the Wire. 
	 * The values of these {@code Wire}s have already been set (they has been <b>computed</b>--hence the name computedWires).
  	 * @return the index of the Truth table output corresponding to the values of the input {@code Wire}s.
  	 */
	private int calculateIndexOfTruthTable(Map<Integer, Wire> computedWires) {
  
		/*
		 * Since a truth table’s order is the order of binary counting, the index of a desired row can be calculated as follows: 
		 * For a truth table with L inputs whose input columns are labeled aL...ai...a2,a1, 
		 * the output index for a given input set is given by: summation from 0 to L : ai *2^i. 
		 * This is calculated below:
		 */
		int truthTableIndex = 0;
		int numberOfInputs = inputWireIndices.length;
		for (int i = numberOfInputs - 1, j = 0; j < numberOfInputs; i--, j++) {
			truthTableIndex += computedWires.get(inputWireIndices[i]).getValue() * Math.pow(2, j);
		}
		return truthTableIndex;
	}

	/**
	 * Returns an array containing the indices of the input {@code Wire}s to this {@code Gate}.
	 * 
	 * @return an array containing the indices of the input {@code Wire}s to this {@code Gate}.
	 */
	public int[] getInputWireIndices() {
		return inputWireIndices;
	}

	/**
	 * Returns the indices of the {@link Wire}s that are the output of this {@code Gate}. <p>
	 * In most circuit designs, this will contain a single wire. 
	 * However, in the case of fan-out > 1, some circuit designers may treat each as separate wires.
	 * 
	 * @return an integer array containing the indices of the {@link Wire}s that are the output to this {@code Gate}.
	 */
	public int[] getOutputWireIndices() {
		return outputWireIndices;
	}

	/**
	 * Returns the {@code Gate}'s truth table.
	 * @return a {@link BitSet} representation of the {@code Gate}'s truth table.
	 */
	public BitSet getTruthTable() {
		return truthTable;
	}

	/**
	 * Returns the {@code Gate}'s number.
     * @return the number of this gate.
  	 */
	public int getGateNumber() {
		return gateNumber;
	}
}
