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

import java.util.BitSet;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.Gate;

/**
 * The Free XOR optimization allows XOR Gates to be evaluated for free -- i.e. without encryption, and thus significantly speeds up Garbled Circuit
 * computations on large circuits with many XOR Gates. <p>
 * The technique dictates a careful way to choose the Wire Values. <p>
 * See the {@link FreeXORGarbledBooleanCircuitUtil} class that constructs the circuit and chooses the values according to this procedure. 
 * Once the Wire values have been chosen as such, evaluating XOR gates does not require encryption. 
 * See the {@link #compute(Map)} method in this class where the computation is done.
 * </p>
 * 
 * See <i>Free XOR Gates and Applications</i> by Validimir Kolesnikov and Thomas Schneider for a full description of the Free XOR technique, pseudocode
 * implementation, as well as the proof of security. 
 * As they mention in that paper, a Free XOR gate with n > 2 inputs can be broken down into n-1 2-input XOR gates. 
 * Hence, we implement the Free XOR optimization for 2-input XOR Gates, and we leave it to the circuit designer to maximize the number of
 * 2-input XOR gates. <p>
 * 
 * @author Steven Goldfeder
 * 
 */
class FreeXORGate implements GarbledGate{

	/* An array containing the indices of the input Wires of this gate. 
	 * The order of the {@code GarbledWire}s in this array is significant as not all functions are symmetric.
	 * For example consider the function ~y v x and the following truth table: 
	 *  x y  ~y v x 
	 *  0 0    1
	 *  0 1    0 
	 *  1 0    1
	 *  1 1    1
	 */
	 protected int[] inputWireIndices;
	  
	 //An array containing the indices of the output {@code GarbledWire}(s).
	 protected int[] outputWireIndices;
	  
	 /*
	  * The number of this {@code FreeXORGarbledGate}. 
	  * This number is used to order {@code FreeXORGarbledGate}s in a {@link FreeXORGarbledBooleanCircuitUtil}.
	  */
	 private int gateNumber;

	 /**
	  * Constructs a free XOR garbled gate from an ungarbled gate.<p>
	  * Since this is an XOR Gate using the Free XOR technique, no encryption is required for its Garbling. 
	  * Rather, the {@code GarbledWire} values were carefully chosen in the GarbledBooleanCircuit.<p> 
	  * See {@code FreeXORGarbledBooleanCircuitUtil} and {@link #compute(Map)} for the  technical details on how this is achieved.
	  * @param ungarbledGate The ungarbled Gate that needs to be Garbled. 
	  */
	 FreeXORGate(Gate ungarbledGate) {
		  inputWireIndices = ungarbledGate.getInputWireIndices();
		  outputWireIndices = ungarbledGate.getOutputWireIndices();
		  gateNumber = ungarbledGate.getGateNumber();
	 }

	 @Override
	 public void compute(Map<Integer, GarbledWire> computedWires) {
	    
		 /*
		  * The Free XOR Gate has only 2 inputs. We XOR the input values to obtain the Garbled output value. 
		  * This is made possible by carefully choosing the garbled values for the {@code Garbled Wires} in the constructor of the
		  * {@code FreeXORGarbledBooleanCircuitUtil} class. See there for details.
		  */
		 byte[] outputValue = computedWires.get(inputWireIndices[0]).getValueAndSignalBit().getEncoded();
	     byte[] nextInput = computedWires.get(inputWireIndices[1]).getValueAndSignalBit().getEncoded();
	
	     // XORing the two input values.
	     for (int currentByte = 0; currentByte < outputValue.length; currentByte++) {
	    	 outputValue[currentByte] ^= nextInput[currentByte];
	     }
	
	     SecretKey outputWireValue = new SecretKeySpec(outputValue, "");
	    
	     // Create the output GarbledWire(s) and set them with the value we just computed
	     for (int w : outputWireIndices) {
	    	 computedWires.put(w, new GarbledWire(outputWireValue));
	     }
	     
	 }

	 @Override
	 public boolean verify(Gate g, Map<Integer, SecretKey[]> allWireValues) {
		 
		//Verify that the gate number and input/output indices are the same as the given ungarbled circuit.
		if (verifyGateComponents(g) == false){
			return false;
		}
	
	    /*
	     * Step 3: Since this is a Free XOR Gate, the ungarbled Gate must be an XOR Gate if they are equivalent. 
	     * Check to see that the truth table is 0110.
	     */
	    BitSet ungarbledTruthTable = g.getTruthTable();
	    if (ungarbledTruthTable.get(0) != false
	        || ungarbledTruthTable.get(1) != true
	        || ungarbledTruthTable.get(2) != true
	        || ungarbledTruthTable.get(3) != false) {
	    	return false;
	    }
	    
	    /*
	     * Step 4: Add the values for the output wire(s) to the allWireValues map. 
	     * This is necessary since the FreeXORGarbledBooleanCircuitUtil's verify method that calls this method needs this map updated since 
	     * subsequent Gates may have this gate's output Wire as an input Wire and need the values to verify equality.
	     * (Non FreeXORGate's need both Wire values to verify the that the truth table's are equal).
	     */
	
	    // First get the 0 output value by using the 0-0 values as inputs and XORing them to get the 0-encoded output. 
	    // The zero value of the 0th GarbledWire in the input array is called zeroZero.
	    byte[] zeroZero = allWireValues.get(inputWireIndices[0])[0].getEncoded();
	    
	    // The zero value of the 1th GarbledWire in the input array is called oneZero.
	    byte[] oneZero = allWireValues.get(inputWireIndices[1])[0].getEncoded();
	    
	    // XOR the values to obtain the result.
	    byte[] outputZero = new byte[zeroZero.length];
	    for (int currentByte = 0; currentByte < zeroZero.length; currentByte++) {
	    	outputZero[currentByte] = (byte) (zeroZero[currentByte] ^ oneZero[currentByte]);
	    }
	    
	    
	    //Next, get the 1 output value by using the 0-1 values as inputs.
	    //The one value of the input GarbledWire with index 1 in the inputwireIndices array is called oneOne.
	    byte[] oneOne = allWireValues.get(inputWireIndices[1])[1].getEncoded();
	    
	    //XOR the 0-1 input values to get the output 1-encoded value.
	    byte[] outputOne = new byte[zeroZero.length];
	    for (int currentByte = 0; currentByte < zeroZero.length; currentByte++) {
	      outputOne[currentByte] = (byte) (zeroZero[currentByte] ^ oneOne[currentByte]);
	    }
	    
	    // Put the result in the output wires.
	    for (int w : outputWireIndices) {
	      allWireValues.put(w, new SecretKey[] { new SecretKeySpec(outputZero, ""),
	          new SecretKeySpec(outputOne, "") });
	    }
	    
	    
	    return true;
	 }

	 /**
	  * Verifies that the gate number and input/output indices are the same as the given ungarbled circuit.
	  * @param g The ungarbled circuit that should be verified.
	  * @return true if verified; false, otherwise.
	  */
	 protected boolean verifyGateComponents(Gate g) {
		/*
		 *  Step 1: Test to see that these gate's are numbered with the same number. if they're not, then for our purposes they are not
		 *  identical. The reason that we treat this as unequal is since in a larger circuit corresponding gates must be identically numbered in 
		 *  order for the circuits to be the same.
		 */
		if (gateNumber != g.getGateNumber()) {
			 return false;
		 }

		// Step 2: Check to ensure that the inputWireIndices and ouputWireIndices are the same.
	    int[] ungarbledInputWireIndices = g.getInputWireIndices();
	    int[] ungarbledOutputWireIndices = g.getOutputWireIndices();
	    int numberOfInputs = inputWireIndices.length;
	    int numberOfOutputs = outputWireIndices.length;
	    if (numberOfInputs != ungarbledInputWireIndices.length || numberOfOutputs != ungarbledOutputWireIndices.length) {
	    	return false;
	    }
	    for (int i = 0; i < numberOfInputs; i++) {
	    	if (inputWireIndices[i] != ungarbledInputWireIndices[i]) {
	    		return false;
	    	}
	    }
	    for (int i = 0; i < numberOfOutputs; i++) {
	    	if (outputWireIndices[i] != ungarbledOutputWireIndices[i]) {
	    		return false;
	    	}
	    }
	    return true;
	}
  
	 @Override
	 public int[] getInputWireIndices() {
		 return inputWireIndices;
	 }
	
	 @Override
	 public int[] getOutputWireIndices() {
		 return outputWireIndices;
	 }
 
}
