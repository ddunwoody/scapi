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
	 * An array containing the integer labels of the input Wire Labels to this gate. 
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
	private int[] inputWireLabels;
  
	/**
	 * An array containing the integer labels of the output {@code Wire}(s).
	 */
	private int[] outputWireLabels;
  
	/**
	 * The integer label of this {@code Gate}. This label is used to order {@code Gate}s in a {@link BooleanCircuit}.
	 */
	private int gateNumber;

	/**
	 * Sets the given values.
	 * @param gateNumber the gate's integer label (in a circuit all gates will be labeled).
	 * @param truthTable a BitSet representation of the final column of a truth table( i.e. the output of the function being computed).
	 * @param inputWireLabels an array containing the labels of the gate's input {@code Wire}s.
	 * @param outputWireLabels an array containing the labels of the gate's input {@code Wire}(s). 
	 * There will generally be a single output {@code Wire}. However in instances in which fan-out of the output {@code Wire} is >1, 
	 * we left the option for treating this as multiple {@code Wire}s.
	 */
	Gate(int gateNumber, BitSet truthTable, int[] inputWireLabels, int[] outputWireLabels) {
	    this.gateNumber = gateNumber;
	    this.truthTable = truthTable;
	    this.inputWireLabels = inputWireLabels;
	    this.outputWireLabels = outputWireLabels;
	}

	/**
	 * Compute the gate operation.<p>
	 * @param computedWires a {@code Map} that maps an integer wire label to the Wire. 
	 * The values of these {@code Wire}s has already been set (it has been <b>computed</b>--hence the name computedWires).
	 */
	void compute(Map<Integer, Wire> computedWires) {
    
		// We call the calculateIndexOfTruthTable method to tell us the position of the output value in the truth table 
		// and look up the value at that position.
		byte outputValue = (byte) ((truthTable.get(calculateIndexOfTruthTable(computedWires))) ? 1 : 0);

		int numberOfOutputs = outputWireLabels.length;
		// Assigns output value to each of this gate's output Wires.
		for (int i = 0; i < numberOfOutputs; i++) {
			computedWires.put(outputWireLabels[i], new Wire(outputValue));
		}
	}

	/**
	 * @param obj a gate that is to be tested for equality to the current {@code Gate}. 
	 * @return {@code true} if the gates are equivalent and {@code false} otherwise.
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Gate)){
			return false;
		}
		Gate g = (Gate) obj;
		
		// First we verify that the gates' integer labels are the same.
		if (gateNumber != g.getGateNumber()) {
			return false;
		}
		
		// Next we verify that the gates' respective truth tables are the same.
		if (!truthTable.equals(g.truthTable)) {
			return false;
		}
		
		// Next we verify that the number of input and output wires to the two respective gates are equal.
		if ((inputWireLabels.length != g.inputWireLabels.length) || (outputWireLabels.length != g.outputWireLabels.length)) {
			return false;
		}
   
		/*
	     * Having determined that the number of input Wire's are the same, we now check that corresponding input wires 
	     * have the same label. As we demonstrated above(in the comments on the imputWireLabel field), the order of the 
	     * wires is significant as not all functions are symmetric. So not only do we care that Wire have the same labels, 
	     * but we also care that the wires with the same label are in the same position of the inputWireLabels array.
	     */
		int numberOfInputs = inputWireLabels.length;
		for (int i = 0; i < numberOfInputs; i++) {
			if (inputWireLabels[i] != g.inputWireLabels[i]) {
				return false;
			}
		}
		
		/*
		 * Having determined that the number of output Wire's are the same, we now check that corresponding output wires have 
		 * the same label.
		 */
		int numberOfOutputs = outputWireLabels.length;
		for (int i = 0; i < numberOfOutputs; i++) {
			if (outputWireLabels[i] != g.outputWireLabels[i]) {
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
	 * @param computedWires a {@code Map} that maps an integer wire label to the Wire. 
	 * The values of these {@code Wire}s has already been set (it has been <b>computed</b>--hence the name computedWires).
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
		int numberOfInputs = inputWireLabels.length;
		for (int i = numberOfInputs - 1, j = 0; j < numberOfInputs; i--, j++) {
			truthTableIndex += computedWires.get(inputWireLabels[i]).getValue() * Math.pow(2, j);
		}
		return truthTableIndex;
	}

	/**
	 * Returns an array containing the integer labels of the input {@code Wire}s to this {@code Gate}.
	 * 
	 * @return an array containing the integer labels of the input {@code Wire}s to this {@code Gate}.
	 */
	public int[] getInputWireLabels() {
		return inputWireLabels;
	}

	/**
	 * AReturns the labels of the {@link Wire}s that are output of this {@code Gate}. <p>
	 * In most circuit designs, this will contain a single wire. 
	 * However, in the case of fan-out > 1, some circuit designers may treat each as separate wires.
	 * 
	 * @return an integer array containing the labels of the {@link Wire}s that are output to this {@code Gate}.
	 */
	public int[] getOutputWireLabels() {
		return outputWireLabels;
	}

	/**
	 * Returns the {@code Gate}'s truth table.
	 * @return a {@link BitSet} representation of the {@code Gate}'s truth table.
	 */
	public BitSet getTruthTable() {
		return truthTable;
	}

	/**
	 * Returns the {@code Gate}'s number(label).
     * @return the number(label) of this gate.
  	 */
	public int getGateNumber() {
		return gateNumber;
	}
}
