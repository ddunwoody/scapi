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
import java.util.BitSet;
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
 * The {@code FreeXORGarbledBooleanCircuit} uses the Free XOR technique that is
 * explained in depth in <i>Free XOR Gates and Applications</i> by Validimir
 * Kolesnikov and Thomas Schneider. This circuit's computes method chooses the
 * wire labels according to the procedure delineated in the above described
 * paper. It then replaces all XOR gates with {@code FreeXOR gates} and these
 * gates can be computed without encryption due to the way the wire's values
 * were chosen. See the above paper also for a proof of security of this method.
 * <p>
 * Note also that the {@link #compute()} method of
 * {@code FreeXORGarbledBooleanCircuit} is no different than the standard
 * {@code StandardGarbledBooleanCircuit}. The reason for this is that we
 * designed the circuit so that the circuit's compute method just calls the
 * gate's verify method. In the compute method, we use the interface
 * {@link GarbledGate} to make our calls and thus the appropriate verify method
 * for the dynamic type of the specified gate is automatically waht is used. For
 * the saem reason, the {@link #verify(BooleanCircuit, Map)} method of
 * {@code FreeXORGarbledBooleanCircuit} is also identical to
 * {@code StandardGarbledBooleanCircuit}'s verify method.
 * </p>
 * 
 * @author Steven Goldfeder
 * 
 */
public class FreeXORGarbledBooleanSubCircuit extends AbstractGarbledBooleanSubCircuit implements Serializable {

	private static final long serialVersionUID = -29845692214028347L;

	/**
	 * The constructor of this class
	 * 
	 * @param ungarbledCircuit
	 *          the circuit that we will garble
	 * @param mes
	 *          The MultiKeyEncryptionScheme that will be used to garble and
	 *          compute this circuit.
	 * @param allInputWireValues
	 *          a map that is passed as a parameter. It should be blank when
	 *          passed as a parameter and the constructor will add to it the 0 and
	 *          1 SecretKey values for each input Wire. The reason that this is
	 *          passed as a parameter and not created here or stored as a field is
	 *          because we need the constructing and only the constructing
	 *          party(from hereon in Alice) to have access to this. The second
	 *          party--i.e. the one that will compute on the circuit(from hereon
	 *          in Bob) should not know which input wire value is 0 and which is 1
	 *          nor should Bob have access to both the 0 and 1 values. Rather, Bob
	 *          is given access to only a single value for each input wire, and he
	 *          does not know what this value encodes. Alice gives Bob the
	 *          appropriate garbled values for her inputs, and Bob gets the value
	 *          for his input from Alice via oblivious transfer. Thus, we have
	 *          designed this class so that only Alice will have access to the map
	 *          with both values of each input wire.
	 *          <p>
	 *          Note that there is one case in which Alice will give this map to
	 *          Bob: In the case of a malicious adversary, Alice will construct
	 *          multiple circuits and Bob will ask Alice to uncover some of them
	 *          to verify them(using our verify method. The way that Alice
	 *          uncovers these is by giving Bob access to the allInputWireValues
	 *          map. Bob calls the verify method and passes this map as well as
	 *          the agreed upon(ungarbled) circuit to the verify method to test
	 *          that Alice constructed the circuit correctly.
	 *          </p>
	 *          <p>
	 *          See <i>Secure Multiparty Computation for Privacy-Preserving Data
	 *          Mining</i> by Yehuda Lindell and Benny Pinkas Section 3 for an
	 *          overview of Yao's protocol, and a more in depth explanation of all
	 *          that is discussed here.
	 *          </p>
	 * @param allOutputWireValues
	 * 			a map that is passed as a parameter. It should be blank when
	 *          passed as a parameter and the constructor will add to it the 0 and
	 *          1 SecretKey values for each output Wire. The reason that this is
	 *          passed as a parameter and not created here or stored as a field is
	 *          because we need the constructing and only the constructing
	 *          party to have access to this. the need to know the output wires keys arises 
	 *          when using sub circuits. That is, the 2 keys of the output wires of the first sub circuit 
	 *          should be passed as a parameter to the second sub circuit and be set as the allInputWireValues parameter.
	 *          This must be, since otherwise the keys of the connecting wires will not match.  
	 * @param translationTable 
	 * 				the translation table to fill.
	 * 
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws KeyNotSetException
	 * @throws TweakNotSetException
	 * @throws PlaintextTooLongException
	 * @throws NoSuchPartyException
	 * @throws CannotBeGarbledExcpetion
	 */
	public FreeXORGarbledBooleanSubCircuit(BooleanCircuit ungarbledCircuit,
			MultiKeyEncryptionScheme mes, 
			Map<Integer, SecretKey[]> allInputWireValues, 
			Map<Integer, SecretKey[]> allOutputWireValues)
					throws InvalidKeyException, IllegalBlockSizeException,
					KeyNotSetException, TweakNotSetException, PlaintextTooLongException, NoSuchPartyException, CannotBeGarbledExcpetion {
		
		
		Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();//the signal bits for every wire in the circuit
		Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>(); 
		subCircuitCreator(ungarbledCircuit, mes, allInputWireValues, allWireValues, signalBits);
		

		//fill the the output wire values to be used in the following sub circuit
		for (int n : outputWireLabels) {
			
			//add both values of output wire labels to the allOutputWireLabels Map that
			//was passed as a parameter
			allOutputWireValues.put(n, allWireValues.get(n));

		}
	}
	
	
	/**
	 * 
	 * Does the actual construction. This is called both from this class constructor and the child class constructor.
	 * 
	 * @param ungarbledCircuit
	 *          the circuit that we will garble
	 * @param mes
	 *          The MultiKeyEncryptionScheme that will be used to garble and
	 *          compute this circuit.
	 * @param allInputWireValues
	 *          a map that is passed as a parameter. It should be blank when
	 *          passed as a parameter and the constructor will add to it the 0 and
	 *          1 SecretKey values for each input Wire. The reason that this is
	 *          passed as a parameter and not created here or stored as a field is
	 *          because we need the constructing and only the constructing
	 *          party(from hereon in Alice) to have access to this. The second
	 *          party--i.e. the one that will compute on the circuit(from hereon
	 *          in Bob) should not know which input wire value is 0 and which is 1
	 *          nor should Bob have access to both the 0 and 1 values. Rather, Bob
	 *          is given access to only a single value for each input wire, and he
	 *          does not know what this value encodes. Alice gives Bob the
	 *          appropriate garbled values for her inputs, and Bob gets the value
	 *          for his input from Alice via oblivious transfer. Thus, we have
	 *          designed this class so that only Alice will have access to the map
	 *          with both values of each input wire.
	 *          <p>
	 *          Note that there is one case in which Alice will give this map to
	 *          Bob: In the case of a malicious adversary, Alice will construct
	 *          multiple circuits and Bob will ask Alice to uncover some of them
	 *          to verify them(using our verify method. The way that Alice
	 *          uncovers these is by giving Bob access to the allInputWireValues
	 *          map. Bob calls the verify method and passes this map as well as
	 *          the agreed upon(ungarbled) circuit to the verify method to test
	 *          that Alice constructed the circuit correctly.
	 *          </p>
	 *          <p>
	 *          See <i>Secure Multiparty Computation for Privacy-Preserving Data
	 *          Mining</i> by Yehuda Lindell and Benny Pinkas Section 3 for an
	 *          overview of Yao's protocol, and a more in depth explanation of all
	 *          that is discussed here.
	 *          </p>
	 * @param allOutputWireValues
	 * 			a map that is passed as a parameter. It should be blank when
	 *          passed as a parameter and the constructor will add to it the 0 and
	 *          1 SecretKey values for each output Wire. The reason that this is
	 *          passed as a parameter and not created here or stored as a field is
	 *          because we need the constructing and only the constructing
	 *          party to have access to this. the need to know the output wires keys arises 
	 *          when using sub circuits. That is, the 2 keys of the output wires of the first sub circuit 
	 *          should be passed as a parameter to the second sub circuit and be set as the allInputWireValues parameter.
	 *          This must be, since otherwise the keys of the connecting wires will not match.  
	 *           
	 * @throws PlaintextTooLongException
	 * @throws TweakNotSetException
	 * @throws KeyNotSetException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeyException
	 * @throws NoSuchPartyException 
	 * @throws CannotBeGarbledExcpetion 
	 */
	protected void subCircuitCreator(BooleanCircuit ungarbledCircuit,
			MultiKeyEncryptionScheme mes, 
			Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, SecretKey[]> allWireValues, Map<Integer, Integer> signalBits)
					throws InvalidKeyException, IllegalBlockSizeException,
					KeyNotSetException, TweakNotSetException, PlaintextTooLongException, NoSuchPartyException, CannotBeGarbledExcpetion {

		
		//initialize member variables
		initVariables(ungarbledCircuit, mes);		
		
		Gate[] ungarbledGates = ungarbledCircuit.getGates();//the built upon boolean circuit
		gates = new GarbledGate[ungarbledGates.length];//the array of garbled gates to be filled
		garbledTables = new byte[ungarbledGates.length][];//the array of garbled tables
		
		/*
		 * The globalKeyOffset is a randomly chosen bit sequence that is the same
		 * size as the key and will be used to create the garbled wire's values
		 * 
		 * We used generate key since this way globalKeyOfset will always be the size
		 * of the key plus permutation bit. See Free XOR Gates and Applications by
		 * Validimir Kolesnikov and Thomas Schneider
		 */
		byte[] globalKeyOffset = mes.generateKey().getEncoded();
		/*
		 * setting the last bit to 1. This follows algorithm 1 step 2 part A of Free
		 * XOR Gates and Applications by Validimir Kolesnikov and Thomas Schneider.
		 * This algorithm calls for XORing the Wire values with R and the signal bit
		 * with 1. So, we set the last bit of R to 1 and this will be XOR'd with the
		 * last bit of the wire value, which is the signal bit in our
		 * implementation.
		 */
		globalKeyOffset[globalKeyOffset.length - 1] |= 1;
		
		
		//set input wire keys (if empty) and the related signal bits
		handleInputWireKeysAndSignalBits(mes, allInputWireValues,
				allWireValues, signalBits, globalKeyOffset);
		
		//generate the gates of the garbled circuits. Either freeXor gates for xor gates or standard gates for other gates
		generateGates(mes, ungarbledGates, allWireValues, signalBits,
				globalKeyOffset);

		
		//copy the input wire values from the map that holds all the wire values to return to the circuit builder
		//setInputWireValuesIfEmpty(allInputWireValues, allWireValues);		
	}
	
	
	
	/**
	 * Empty constructor
	 */
	protected  FreeXORGarbledBooleanSubCircuit(){
		
	}

	protected void setInputWireValuesIfEmpty(
			Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, SecretKey[]> allWireValues) {
		/*
		 * add both values of input wire labels to the allInputWireLabels Map that
		 * was passed as a parameter
		 */
		if(allInputWireValues.isEmpty()){
			for (int w : partyOneInputWireLabels) {
				allInputWireValues.put(w, allWireValues.get(w));
			}
			for (int w : partyTwoInputWireLabels) {
	            allInputWireValues.put(w, allWireValues.get(w));
	        }
		}
	}

	/**
	 * Inits the member variables of the class
	 * @param ungarbledCircuit
	 * @param mes
	 * @throws NoSuchPartyException
	 * @throws CannotBeGarbledExcpetion
	 */
	protected void initVariables(BooleanCircuit ungarbledCircuit,
			MultiKeyEncryptionScheme mes) throws NoSuchPartyException,
			CannotBeGarbledExcpetion {
		this.mes = mes;
		
		outputWireLabels = ungarbledCircuit.getOutputWireLabels();
		partyOneInputWireLabels = ungarbledCircuit.getInputWireLabels(1);
	    partyTwoInputWireLabels = ungarbledCircuit.getInputWireLabels(2);
	    
	    if(ungarbledCircuit.getNumberOfParties() !=2){
			  throw new CannotBeGarbledExcpetion("Only a two party circuit can be garbled!");
		}
	    
		if(partyOneInputWireLabels.size()==0){
		  isPartyOneInputSet=true;
		}
	    if(partyTwoInputWireLabels.size()==0){
          isPartyTwoInputSet=true;
        }
		
	    numberOfWires = ungarbledCircuit.getNumberOfWires();
	}

	/**
	 * Set input wire keys (if empty) and the related signal bits
	 *
	 * @param globalKeyOffset a set key that is the xor of all the 0 and 1 keys
	 */
	protected void handleInputWireKeysAndSignalBits(MultiKeyEncryptionScheme mes,
			Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, SecretKey[]> allWireValues,
			Map<Integer, Integer> signalBits, byte[] globalKeyOffset) {
		if(allInputWireValues.isEmpty()){//we need to create the secret keys
			
			for (int w : partyOneInputWireLabels) {
				fillInputsData(mes, allWireValues, signalBits, globalKeyOffset,	w);
				
				//add to the input keys map
				allInputWireValues.put(w, allWireValues.get(w));
			}
			for (int w : partyTwoInputWireLabels) {
	          fillInputsData(mes, allWireValues, signalBits, globalKeyOffset, w);
	          
	        //add to the input keys map
	          allInputWireValues.put(w, allWireValues.get(w));
	      }
		}
		else{
			//set the keys of the input wires
			allWireValues.putAll(allInputWireValues);
			
			//deduce the input signal bits and the global key offset from allInputWireValues
			int j=0;
			for (int w : partyOneInputWireLabels) {
				//the 0 key
				j = extractInputSignalBits(allInputWireValues, signalBits,
						globalKeyOffset, j, w);
				
			}
			for (int w : partyTwoInputWireLabels) {
				j = extractInputSignalBits(allInputWireValues, signalBits,
						globalKeyOffset, j, w);
	      }
			
		}
	}

	/**
	 * Generate the gates of the garbled circuits. Either freeXor gates for xor gates or standard gates for other gates
	 * 
	 */
	protected void generateGates(MultiKeyEncryptionScheme mes,
			Gate[] ungarbledGates, Map<Integer, SecretKey[]> allWireValues,
			Map<Integer, Integer> signalBits, byte[] globalKeyOffset)
			throws InvalidKeyException, IllegalBlockSizeException,
			KeyNotSetException, TweakNotSetException, PlaintextTooLongException {
		// create the XOR and XORNOT truth table to be used to test against for equality
		BitSet XORTruthTable = new BitSet();
		BitSet XORNOTTruthTable = new BitSet();

		XORTruthTable = new BitSet();
		XORTruthTable.set(1);
		XORTruthTable.set(2);

		XORNOTTruthTable = new BitSet();
		XORNOTTruthTable.set(0);
		XORNOTTruthTable.set(3);
		
		
		for (int gate = 0; gate < ungarbledGates.length; gate++) {
			SecretKey zeroValue;
			SecretKey oneValue;
			if (ungarbledGates[gate].getTruthTable().equals(XORTruthTable)) {
				byte[] zeroValueBytes = allWireValues.get(ungarbledGates[gate]
						.getInputWireLabels()[0])[0].getEncoded();// bytes of first input
				for (int i = 1; i < ungarbledGates[gate].getInputWireLabels().length; i++) {
					byte[] nextInput = allWireValues.get(ungarbledGates[gate]
							.getInputWireLabels()[i])[0].getEncoded();
					for (int currentByte = 0; currentByte < zeroValueBytes.length; currentByte++) {
						zeroValueBytes[currentByte] ^= nextInput[currentByte];
					}
				}
				byte[] oneValueBytes = new byte[zeroValueBytes.length];
				for (int i = 0; i < zeroValueBytes.length; i++) {
					oneValueBytes[i] = (byte) (zeroValueBytes[i] ^ globalKeyOffset[i]);
				}
				int signalBit = (zeroValueBytes[zeroValueBytes.length - 1] & 1) == 0 ? 0
						: 1;
				
				signalBits.put(ungarbledGates[gate].getOutputWireLabels()[0], signalBit);
				zeroValue = new SecretKeySpec(zeroValueBytes, "");
				oneValue = new SecretKeySpec(oneValueBytes, "");

				allWireValues.put(ungarbledGates[gate].getOutputWireLabels()[0],
						new SecretKey[] { zeroValue, oneValue });

				gates[gate] = new FreeXORGateSlim(ungarbledGates[gate]);
				
				
			} 
			//XOR NOT gate
			else if (ungarbledGates[gate].getTruthTable().equals(XORNOTTruthTable)) {
				byte[] zeroValueBytes = allWireValues.get(ungarbledGates[gate]
						.getInputWireLabels()[0])[0].getEncoded();// bytes of first input
				
				byte[] oneOutputBytes = new byte[zeroValueBytes.length];
				
				for (int i = 1; i < ungarbledGates[gate].getInputWireLabels().length; i++) {
					byte[] nextInput = allWireValues.get(ungarbledGates[gate]
							.getInputWireLabels()[i])[0].getEncoded();
					for (int currentByte = 0; currentByte < zeroValueBytes.length; currentByte++) {
						oneOutputBytes[currentByte] = (byte) (zeroValueBytes[currentByte] ^ nextInput[currentByte]);
					}
				}
				byte[] zeroOutputBytes = new byte[oneOutputBytes.length];
				for (int i = 0; i < zeroValueBytes.length; i++) {
					zeroOutputBytes[i] = (byte) (oneOutputBytes[i] ^ globalKeyOffset[i]);
				}
				int signalBit = (zeroOutputBytes[zeroOutputBytes.length - 1] & 1) == 0 ? 0
						: 1;
				
				signalBits.put(ungarbledGates[gate].getOutputWireLabels()[0], signalBit);
				zeroValue = new SecretKeySpec(zeroOutputBytes, "");
				oneValue = new SecretKeySpec(oneOutputBytes, "");

				allWireValues.put(ungarbledGates[gate].getOutputWireLabels()[0],
						new SecretKey[] { zeroValue, oneValue });

				gates[gate] = new FreeXORNOTGate(ungarbledGates[gate]);
				
			}
			
			else {
				zeroValue = mes.generateKey();
				byte[] zeroValueBytes = zeroValue.getEncoded();
				byte[] oneValueBytes = new byte[zeroValueBytes.length];
				int signalBit = (zeroValueBytes[zeroValueBytes.length - 1] & 1) == 0 ? 0
						: 1;
				signalBits
				.put(ungarbledGates[gate].getOutputWireLabels()[0], signalBit);
				for (int i = 0; i < zeroValueBytes.length; i++) {
					oneValueBytes[i] = (byte) (zeroValueBytes[i] ^ globalKeyOffset[i]);
				}

				zeroValue = new SecretKeySpec(zeroValueBytes, "");
				oneValue = new SecretKeySpec(oneValueBytes, "");

				allWireValues.put(ungarbledGates[gate].getOutputWireLabels()[0],
						new SecretKey[] { zeroValue, oneValue });
				gates[gate] = new StandardGarbledGate(this, ungarbledGates[gate],
						allWireValues, signalBits);
				
			}

		}
	}

	//set the signal bits using the input wire values 
	protected int extractInputSignalBits(
			Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, Integer> signalBits, byte[] globalKeyOffset, int j,
			int w) {
		
		SecretKey zeroValue = allInputWireValues.get(w)[0];
		SecretKey oneValue = allInputWireValues.get(w)[1];
		byte[] zeroValueBytes = zeroValue.getEncoded();
		int signalBit = (zeroValueBytes[zeroValueBytes.length - 1] & 1) == 0 ? 0
				: 1;
		signalBits.put(w, signalBit);
		byte[] oneValueBytes = oneValue.getEncoded();
		
		//setting the global key should be done once
		if(j==0){
			for (int i = 0; i < zeroValueBytes.length; i++) {
				globalKeyOffset[i] = (byte) (oneValueBytes[i] ^ zeroValueBytes[i]);
			}
		}
		
		j++;
		return j;
	}

	/**
	 * set the wire keys and signal bits.
	 * 
	 * @param w the wire label
	 */
	protected void fillInputsData(MultiKeyEncryptionScheme mes,
			Map<Integer, SecretKey[]> allWireValues,
			Map<Integer, Integer> signalBits, byte[] globalKeyOffset, int w) {
		SecretKey zeroValue = mes.generateKey();
		SecretKey oneValue;
		byte[] zeroValueBytes = zeroValue.getEncoded();
		int signalBit = (zeroValueBytes[zeroValueBytes.length - 1] & 1) == 0 ? 0
				: 1;
		signalBits.put(w, signalBit);
		byte[] oneValueBytes = new byte[zeroValueBytes.length];
		for (int i = 0; i < zeroValueBytes.length; i++) {
			oneValueBytes[i] = (byte) (zeroValueBytes[i] ^ globalKeyOffset[i]);
		}
		oneValue = new SecretKeySpec(oneValueBytes, "");
		allWireValues.put(w, new SecretKey[] { zeroValue, oneValue });
	}
}
