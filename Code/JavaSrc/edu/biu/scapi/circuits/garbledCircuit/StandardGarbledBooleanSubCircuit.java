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

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.CannotBeGarbledExcpetion;
import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.exceptions.TweakNotSetException;

/**
 * The {@StandardGarbledBooleanCircuit} class is a Garbled
 * Boolean Circuit without optimizations (e.g. the Free XOR technique and row
 * reduction technique etc. are not used)
 * 
 * @author Steven Goldfeder
 * 
 */

public class StandardGarbledBooleanSubCircuit extends AbstractGarbledBooleanSubCircuit
implements Serializable {

	private static final long serialVersionUID = 5053750793775690854L;

	/**
	 * @param ungarbledCircuit
	 *          the circuit that we will garble
	 * @param mes
	 *          The MultiKeyEncryptionScheme that will be used to garble and
	 *          compute this circuit.
	 * @param allInputWireValues
	 *          a map that is passed as a parameter. It is either blank when
	 *          passed as a parameter and the constructor will add to it the 0 and
	 *          1 SecretKey values for each input Wire. Or can be set before and the 
	 *          constructor will use the pre-defined keys. The reason that this is
	 *          passed as a parameter and not stored as a field is
	 *          because we need the constructing and only the constructing
	 *          party(from hereon in PartyOne) to have access to this. The second
	 *          party--i.e. the one that will compute on the circuit(from hereon
	 *          in PartyTwo) should not know which input wire value is 0 and which is 1
	 *          nor should PartyTwo have access to both the 0 and 1 values. Rather, PartyTwo
	 *          is given access to only a single value for each input wire, and he
	 *          does not know what this value encodes. PartyOne gives PartyTwo the
	 *          appropriate garbled values for her inputs, and PartyTwo gets the value
	 *          for his input from PartyOne via oblivious transfer. Thus, we have
	 *          designed this class so that only PartyOne will have access to the map
	 *          with both values of each input wire.
	 *          <p>
	 *          Note that there is one case in which PartyOne will give this map to
	 *          PartyTwo: In the case of a malicious adversary, PartyOne will construct
	 *          multiple circuits and PartyTwo will ask PartyOne to uncover some of them
	 *          to verify them(using our verify method. The way that PartyOne
	 *          uncovers these is by giving PartyTwo access to the allInputWireValues
	 *          map. PartyTwo calls the verify method and passes this map as well as
	 *          the agreed upon(ungarbled) circuit to the verify method to test
	 *          that PartyOne constructed the circuit correctly.
	 *          </p>
	 *          <p>
	 *          See <i>Secure Multiparty Computation for Privacy-Preserving Data
	 *          Mining</i> by Yehuda Lindell and Benny Pinkas Section 3 for an
	 *          overview of Yao's protocol, and a more in depth explanation of all
	 *          that is discussed here.
	 *          </p>
	 *          
	 * @param inputTranslationTable the translation table of the input. It is important when the input keys are given
	 * 								as a parameter. The relates signal bits must be supplied too in this case.
	 * @param allOutputWireValues this is for the next sub circuit to be set as the input wire keys
	 * @param translationTable this is for the next sub circuit to be set as the input signal bits
	 * 
	 * @throws PlaintextTooLongException 
	 * @throws TweakNotSetException 
	 * @throws KeyNotSetException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 * @throws CannotBeGarbledExcpetion 
	 * @throws NoSuchPartyException 
	 */

	public StandardGarbledBooleanSubCircuit(BooleanCircuit ungarbledCircuit,
			MultiKeyEncryptionScheme mes,
			Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, Integer> inputTranslationTable,
			Map<Integer, SecretKey[]> allOutputWireValues, Map<Integer, Integer> translationTable) 
			throws InvalidKeyException, IllegalBlockSizeException, KeyNotSetException, TweakNotSetException, PlaintextTooLongException, CannotBeGarbledExcpetion, NoSuchPartyException {
		
		
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
		Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();
		
		
		subCircuitCreator(ungarbledCircuit, mes, allInputWireValues,
				inputTranslationTable, allWireValues, signalBits);
		/*
		 * add the output wire labels' signal bits to the translation table. For a
		 * full understanding on why we chose to implement the translation table
		 * this way, see the documentation to the translationTable field of
		 * AbstractGarbledBooleanCircuit
		 */
		for (int n : outputWireLabels) {
			translationTable.put(n, signalBits.get(n));
			
			//add both values of output wire labels to the allOutputWireLabels Map that
			//was passed as a parameter
			allOutputWireValues.put(n, allWireValues.get(n));

		}
		 
	}


	/**
	 * Empty constructor
	 */
	public StandardGarbledBooleanSubCircuit() {
	}

	/**
	 * 
	 * Does the actual construction. This is called both from this class constructor and the child class constructor.
	 * 
	 */
	protected void subCircuitCreator(BooleanCircuit ungarbledCircuit,
			MultiKeyEncryptionScheme mes,
			Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, Integer> inputTranslationTable,
			Map<Integer, SecretKey[]> allWireValues,
			Map<Integer, Integer> signalBits) throws CannotBeGarbledExcpetion,
			NoSuchPartyException, InvalidKeyException,
			IllegalBlockSizeException, KeyNotSetException,
			TweakNotSetException, PlaintextTooLongException {
		this.mes = mes;
		outputWireLabels = ungarbledCircuit.getOutputWireLabels();
		if(ungarbledCircuit.getNumberOfParties() !=2){
		  throw new CannotBeGarbledExcpetion("Only a two party circuit can be garbled!");
		}
		partyOneInputWireLabels = ungarbledCircuit.getInputWireLabels(1);
		if(partyOneInputWireLabels.size()==0){
		  isPartyOneInputSet=true;
		}
	    partyTwoInputWireLabels = ungarbledCircuit.getInputWireLabels(2);
	    if(partyTwoInputWireLabels.size()==0){
          isPartyTwoInputSet=true;
        }
		Gate[] ungarbledGates = ungarbledCircuit.getGates();
		numberOfWires = ungarbledCircuit.getNumberOfWires();
		gates = new StandardGarbledGate[ungarbledGates.length];
		
		garbledTables = new byte[ungarbledGates.length][];
		SecureRandom random = new SecureRandom();

		
		if(allInputWireValues.isEmpty()){//we need to create the secret keys and signal bits
			
			for (int w : partyOneInputWireLabels) {
				fillIWireKeysAndSignalBit(mes, allInputWireValues, inputTranslationTable, random, w);
			}
			for (int w : partyTwoInputWireLabels) {
				fillIWireKeysAndSignalBit(mes, allInputWireValues, inputTranslationTable, random, w);
	      }
		}
		
			
		//set the keys of the input wires and the signal bits. Either filled here in the constructor or given as an argument
		allWireValues.putAll(allInputWireValues);
		signalBits.putAll(inputTranslationTable);
			
		
		// now that all wires have garbled values, we create the individual garbled
		// gates
		for (int gate = 0; gate < gates.length; gate++) {
			
			//for each gate fill the keys and signal bits for output wires since they are not filled yet.
			for (int i = 0; i < ungarbledGates[gate].getOutputWireLabels().length; i++) {
				
				fillIWireKeysAndSignalBit(mes, allWireValues, signalBits, random, ungarbledGates[gate].getOutputWireLabels()[i]);
			}
			

			gates[gate] = new StandardGarbledGate(this, ungarbledGates[gate], allWireValues,
					signalBits);
		}
	}


	/**
	 * Builds both keys of wire {@code w} and a random signal bit. 
	 */
	private void fillIWireKeysAndSignalBit(MultiKeyEncryptionScheme mes,
			Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, Integer> signalBits, SecureRandom random, int wireLabel) {
		
		/*
		 * assign a 0-encoded value and a 1-encoded value for each GarbledWire.
		 * These are the two possible values that the given GarbledWire can be set
		 * to.
		 */
		SecretKey zeroValue = mes.generateKey();
		SecretKey oneValue = mes.generateKey();
		// Assigns a 0 or 1 as the signal bit for the current wire
		int signalBit = random.nextInt(2);
		signalBits.put(wireLabel, signalBit);
		// put the signal bits on the wires
		int signalOnZeroValue = signalBit ^ 0;

		if (signalOnZeroValue == 0) {
			// set the signal bit on the 0-value for the wire. This is the last bit
			// of the wire's 0 value(key)
			byte[] value = zeroValue.getEncoded();
			value[value.length - 1] &= 254;
			zeroValue = new SecretKeySpec(value, "");
			// set the signal bit on the 1-value for the wire. This is the last bit
			// of the wire's 1 value(key)
			value = oneValue.getEncoded();
			value[value.length - 1] |= 1;
			oneValue = new SecretKeySpec(value, "");
		} else if (signalOnZeroValue == 1) {
			// // set 0-value signal bit. This is the last bit of the wire's 0
			// value(key)
			byte[] value = zeroValue.getEncoded();
			value[value.length - 1] |= 1;
			zeroValue = new SecretKeySpec(value, "");
			// set the 1-value signal bit. This is the last bit of the wire's 1
			// value(key)
			value = oneValue.getEncoded();
			value[value.length - 1] &= 254;
			oneValue = new SecretKeySpec(value, "");
		}
		// put the 0-value and the 1-value on the allWireValuesMap
		allInputWireValues.put(wireLabel, new SecretKey[] { zeroValue, oneValue });
	}
	
}
