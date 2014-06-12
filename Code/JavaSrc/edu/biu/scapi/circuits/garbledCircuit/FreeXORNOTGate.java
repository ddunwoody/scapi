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
 * This class implements XOR followed by a NOT gate. <p>
 * We still use the technique of free XOR, the difference is in the garbled values of the wires. 
 * 
 * @author Steven Goldfeder
 * 
 */
class FreeXORNOTGate extends FreeXORGate{

	
	  
	/**
	 * Constructs a free XOR NOT garbled gate from an ungarbled gate.<p>
	 * Since this is an XOR NOT Gate using the Free XOR technique, no encryption is required for its Garbling. 
	 * Rather, the {@code GarbledWire} values were carefully chosen in the GarbledBooleanCircuit. <p>
	 * See {@code FreeXORGarbledBooleanCircuitUtil} and {@link #compute(Map)} for the  technical details on how this is achieved.
	 * @param ungarbledGate The ungarbled Gate that needs to be Garbled. 
	 */
	FreeXORNOTGate(Gate ungarbledGate) {
	    super(ungarbledGate);
	}
	
	@Override
	public boolean verify(Gate g, Map<Integer, SecretKey[]> allWireValues) {
    
		//Verify that the gate number and input/output indices are the same as the given ungarbled circuit.
		if (verifyGateComponents(g) == false){
			return false;
		}
		
		/*
	     * Step 3: Since this is a Free XOR NOT Gate, the ungarbled Gate must be an XOR NOT Gate if they are equivalent. 
	     * Check to see that the truth table is 1001.
	     */
	    BitSet ungarbledTruthTable = g.getTruthTable();
	    if (ungarbledTruthTable.get(0) != true
	        || ungarbledTruthTable.get(1) != false
	        || ungarbledTruthTable.get(2) != false
	        || ungarbledTruthTable.get(3) != true) {
	      return false;
	    }
	    
	    /*
	     * Step 4: Add the values for the output wire(s) to the allWireValues map. 
	     * This is necessary since the FreeXORGarbledBooleanCircuitUtil's verify method that calls this method needs this map updated since 
	     * subsequent Gates may have this gate's output Wire as an input Wire and need the values to verify equality.
	     * (Non FreeXORGate's need both Wire values to verify the that the truth table's are equal).
	     */
	
	    // First get the 1 output value by using the 0-0 values as inputs and XORing them to get the 0-encoded output. 
	    // The zero value of the 0th GarbledWire in the input array is called zeroZero.
	    byte[] zeroZero = allWireValues.get(inputWireIndices[0])[0].getEncoded();
	 
	    // The zero value of the 1th GarbledWire in the input array is called oneZero.
	    byte[] oneZero = allWireValues.get(inputWireIndices[1])[0].getEncoded();
	    
	    // XOR the values to obtain the result.
	    byte[] outputOne = new byte[zeroZero.length];
	    for (int currentByte = 0; currentByte < zeroZero.length; currentByte++) {
	    	outputOne[currentByte] = (byte) (zeroZero[currentByte] ^ oneZero[currentByte]);
	    }
	    
	    
	    //Next, get the 1 output value by using the 0-1 values as inputs.
	    //The one value of the input GarbledWire with index 1 in the inputwireIndices array is called oneOne.
	    byte[] oneOne = allWireValues.get(inputWireIndices[1])[1].getEncoded();

	    //XOR the 0-1 input values to get the output 0-encoded value.
	    byte[] outputZero = new byte[zeroZero.length];
	    for (int currentByte = 0; currentByte < zeroZero.length; currentByte++) {
	    	outputZero[currentByte] = (byte) (zeroZero[currentByte] ^ oneOne[currentByte]);
	    }
	    
	    // Put the result in the output wires.
	    for (int w : outputWireIndices) {
	      allWireValues.put(w, new SecretKey[] { new SecretKeySpec(outputZero, ""),
	          new SecretKeySpec(outputOne, "") });
	    }
	    return true;
	}
  

}
