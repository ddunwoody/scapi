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

import edu.biu.scapi.circuits.circuit.Wire;

/**
 * This class does some functionalities that are particular to circuits and do not exist in sub circuits. Since a class can only
 * inherit from one class and circuit already inherit from AbstractGarbledBooleanSubCircuit, circuits will use this class as a composition.
 * Unlike sub circuits, circuits have translation tables. To avoid code duplication, functionlity that includes translation resides in
 * this class.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class CircuitUtil {

	
	  /**
	   * 
	   * 
	   * Creates Wires and thus has the 
	   * benefit of being uniform with our regular (nongarbled) circuit implementation.
	   */
	
	/**
	 * 
	 * @param garbledOutput the result of computing the circuit. This is result is given in garbled wires and will be translation according to the 
	 *        translation table.
	 * @param translationTable the signal bits of the output wires. Used to translate the garbled result.
	 * @param outputWireLabels the labels of the output wires
	 * @return the translated results as wires of the boolean circuit where the value of the wires are set.
	 */
	  public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput, Map<Integer, Integer> translationTable, int[] outputWireLabels) {
		  
	    Map<Integer, Wire> translatedOutput = new HashMap<Integer, Wire>();
	    
	    //go through the output wires
	    for (int w : outputWireLabels) {
	      int signalBit = translationTable.get(w);
	      int permutationBitOnWire = garbledOutput.get(w).getSignalBit();
	      
	      //calc the resulting value
	      int value = signalBit ^ permutationBitOnWire;
	      System.out.print(value);
	      
	      //hold the result as a wire
	      Wire translated = new Wire(value);
	      translatedOutput.put(w, translated);
	    }
	    System.out.println();
	    return translatedOutput;

	  }
	
	  /**
	   * 
	   * Verifies that the 0-wire translates to a 0 and that the 1 wire translates to a 1
	   * 
	   * @param translationTable 
	   * @param outputWireLabels the output wire labels
	   * @param allWireValues both keys of each wire. Should contain the values of the output wires.
	   * @return
	   */
	  public boolean verifyCircuitTranslation(Map<Integer, Integer> translationTable,
		      int[] outputWireLabels, Map<Integer, SecretKey[]> allWireValues) {
		 
	  /*
	     * check that the output wires translate correctly. 
	     * At this point, we have gone through the entire
	     * circuit so allWireValues now contains both possible values for every wire
	     * in the circuit. We check the output wire values and make sure that the
	     * 0-wire translates to a 0 and that the 1 wire translates to a 1.
	     */
	    for (int w : outputWireLabels) {
	      SecretKey zeroValue = allWireValues.get(w)[0];
	      SecretKey oneValue = allWireValues.get(w)[1];

	      int signalBit = translationTable.get(w);
	      int permutationBitOnZeroWire = (zeroValue.getEncoded()[zeroValue
	          .getEncoded().length - 1] & 1) == 0 ? 0 : 1;
	      int permutationBitOnOneWire = (oneValue.getEncoded()[oneValue
	          .getEncoded().length - 1] & 1) == 0 ? 0 : 1;
	      int translatedZeroValue = signalBit ^ permutationBitOnZeroWire;
	      int translatedOneValue = signalBit ^ permutationBitOnOneWire;
	      if (translatedZeroValue != 0 || translatedOneValue != 1) {
	        return false;
	      }
	    }
		return true;
	  }

}
