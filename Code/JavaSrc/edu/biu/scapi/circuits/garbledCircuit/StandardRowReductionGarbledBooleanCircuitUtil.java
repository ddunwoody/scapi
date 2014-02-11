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

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.BitSet;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;

/**
 * The {StandardRowReductionGarbledBooleanCircuit} class is a utility class that computes the functionalities regarding Garbled Boolean Circuit 
 * using the row reduction technique.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class StandardRowReductionGarbledBooleanCircuitUtil extends StandardGarbledBooleanCircuitUtil {
	
	protected KeyDerivationFunction kdf;
	protected boolean isRowReductionWithFixedOutputKeys;
	
	/**
	 * Sets the given MultiKeyEncryptionScheme, kdf and random.
	 * @param mes
	 * @param kdf
	 * @param random
	 * @param isRowReductionWithFixedOutputKeys indicates if the user is going to use sample the wires' keys out of given output keys. 
	 * In this case, the circuit representation should be a little different. 
	 * See {@link BooleanCircuit#BooleanCircuit(File f)} for more information.
	 */
	StandardRowReductionGarbledBooleanCircuitUtil(MultiKeyEncryptionScheme mes, KeyDerivationFunction kdf, SecureRandom random, boolean isRowReductionWithFixedOutputKeys) {
		super(mes, random);
		this.kdf = kdf;	
		this.isRowReductionWithFixedOutputKeys = isRowReductionWithFixedOutputKeys;
	}
	
	/**
	 * Default constructor.
	 */
	StandardRowReductionGarbledBooleanCircuitUtil(){
		super();
	}
	
	/**
	 * Creates a RowReductionGarbledGate.
	 * @param ungarbledGate to garble.
	 * @param garbledTablesHolder
	 * @return the created gate.
	 */
	protected GarbledGate createGate(Gate ungarbledGate, GarbledTablesHolder garbledTablesHolder) {
		BitSet XORZeroTruthTable = new BitSet();
		XORZeroTruthTable.set(1);
		if(ungarbledGate.getTruthTable().equals(XORZeroTruthTable)){
			return new StandardGarbledGate(ungarbledGate, mes, garbledTablesHolder);
		} else{
			return new StandardRowReductionGarbledGate(ungarbledGate, mes, kdf, garbledTablesHolder);
		}
	}
	
	/**
	 * Generates wires' keys.<P>
	 * In case of row reduction, the user can give the output keys only if he set the isRowReductionWithFixedOutputKeys to true in the constructor.
	 * @throws IllegalArgumentException if the user gave the output keys while the isRowReductionWithFixedOutputKeys set to false.
	 */
	@Override
	public CircuitCreationValues generateWireKeysAndSetTables(BooleanCircuit ungarbledCircuit, GarbledTablesHolder garbledTablesHolder, 
			GarbledGate[] gates, Map<Integer, SecretKey[]> partialWireValues) {
		if (partialWireValues.containsKey(ungarbledCircuit.getOutputWireLabels()[0]) && !isRowReductionWithFixedOutputKeys){
			throw new IllegalArgumentException("Cannot accept output wires' keys when Row Reduction with fixed keys is not declared");
		}
		return super.generateWireKeysAndSetTables(ungarbledCircuit, garbledTablesHolder, gates, partialWireValues);
	}
	
	/**
	 * Creates a RowReductionGarbledGate and fill its garbled table.
	 */
	protected void generateOutputKeys(Map<Integer, SecretKey[]> allOutputWireValues, Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues) {
		BitSet XORZeroTruthTable = new BitSet();
		XORZeroTruthTable.set(1);
		if(!ungarbledGate.getTruthTable().equals(XORZeroTruthTable)){
		
			//Sample the value to the key that is not generated by the row reduction technique.
			byte[] otherBytes = mes.generateKey().getEncoded();
			
			//Call the function that calculate the output key according to the row reduction technique.
			generateRowReductionOutputKeys(allWireValues, ungarbledGate, otherBytes);
		} else{
			super.generateOutputKeys(allOutputWireValues, ungarbledGate, allWireValues);
		}
		
	}
	

	@Override
	protected void generateOutputKeysFromSeed(PseudorandomGenerator prg,Map<Integer, SecretKey[]> allWireValues, Gate ungarbledGate) {
		//Sample the value to the key that is not generated by the row reduction technique.
		byte[] otherBytes = new byte[mes.getCipherSize()];
		prg.getPRGBytes(otherBytes, 0, mes.getCipherSize());
		
		//Call the function that calculate the output key according to the row reduction technique.
		generateRowReductionOutputKeys(allWireValues, ungarbledGate, otherBytes);
		
	}

	/**
	 * Samples keys to the output wires with the row reduction technique.
	 * @param allWireValues a map that contains both keys for each wire.
	 * @param ungarbledGate the gate we want to sample keys for its output wires.
	 * @param otherBytes the value to the key that is not generated by the row reduction technique.
	 */ 
	private void generateRowReductionOutputKeys(Map<Integer, SecretKey[]> allWireValues, Gate ungarbledGate, byte[] otherBytes) {
		int[] labels = ungarbledGate.getInputWireLabels();
		int numberOfInputs = labels.length;
		
		//The number of rows is 2^numberOfInputs - 1. The last row will be calculated by the row reduction technique.
		int numberOfRows = (int) Math.pow(2, numberOfInputs)-1;
		
		//Find the line that we do not save in the table and we use the KDF to find the value of the output key.
		for (int rowOfTruthTable = 0; (rowOfTruthTable <= numberOfRows) && !(allWireValues.containsKey(ungarbledGate.getOutputWireLabels()[0])); rowOfTruthTable++) {
		  	int permutedPosition = 0;
		  	for (int i = 0, j = (int) Math.pow(2, numberOfInputs - 1), reverseIndex = numberOfInputs - 1; i < numberOfInputs; i++, j /= 2, reverseIndex--) {
		  	
		  		/* Truth table inputs are arranged according to binary number values. j is the value that begins as a 1 in the
			   	 * leftmost(most significant bit) of the binary number that is the size of the truth table. Say for example that there are
			   	 * 3 inputs. So the truth table has 3 input columns. j begins as the binary number 100 and we use it to check whether the leftmost bit in
			   	 * the row of the truth table is set. If it is, that means that the input value is a 1.  Otherwise it's a 0. We then divide j by 2 to obtain the binary
			   	 * number 010 and we use this to determine the value of the inputs in the second column. We then divide by 2 again to obtain the 
			   	 * binary number 001 and use it to determine the value of the inputs in the third column.
			   	 */
		  		int input = (((rowOfTruthTable & j) == 0) ? 0 : 1);
		  		
		  		if (allWireValues.get(labels[i]) == null){
		  			System.out.println("missing keys for " +labels[i]);
		  		}
		  		//signal bit is the last bit of k0.
		  		byte[] k0 = allWireValues.get(labels[i])[0].getEncoded();
		  		byte signalBit =  (byte) (k0[k0.length-1] & 1);
		  		
		  		permutedPosition += (input ^ signalBit) * (Math.pow(2, reverseIndex));
		  		
		  	}
		  	
		  	//This is the row that we do not save in the table but calculate the value via KDF.
		  	if (permutedPosition == numberOfRows){
		  		//Get the indexes of the input keys.
		  		int wire0Key = ((rowOfTruthTable & 2) == 0) ? 0 : 1;
		  		int wire1Key = ((rowOfTruthTable & 1) == 0) ? 0 : 1;
		  		
		  		//Get the input keys.
		  		SecretKey input0 = allWireValues.get(labels[0])[wire0Key];
		  		SecretKey input1 = allWireValues.get(labels[1])[wire1Key];
		  		
		  		//Calculate the output key via KDF.
		  		ByteBuffer kdfBytes = ByteBuffer.allocate(mes.getCipherSize()*numberOfInputs +16);
				kdfBytes.put(input0.getEncoded());
				kdfBytes.put(input1.getEncoded());
				kdfBytes.putInt(ungarbledGate.getGateNumber());
				kdfBytes.putInt((input0.getEncoded()[input0.getEncoded().length - 1] & 1) == 0 ? 0 : 1);
				kdfBytes.putInt((input1.getEncoded()[input1.getEncoded().length - 1] & 1) == 0 ? 0 : 1);
				SecretKey wireValue = kdf.deriveKey(kdfBytes.array(), 0, mes.getCipherSize()*numberOfInputs +16, mes.getCipherSize());
				
				//Now we have both values, calculate the signal bit.
				boolean output = ungarbledGate.getTruthTable().get(rowOfTruthTable);
				byte signalBit = 0;
				SecretKey zeroKey, oneKey;
				if (output == false){
					zeroKey = wireValue;
					signalBit = (byte) (wireValue.getEncoded()[wireValue.getEncoded().length - 1] & 1);
					if (signalBit == 0){
						otherBytes[otherBytes.length-1] |= 1;	
					} else{
						otherBytes[otherBytes.length-1] &= 254;
					}
					oneKey = new SecretKeySpec(otherBytes, "");
				} else {
					oneKey = wireValue;
					signalBit = (byte) (1 - (wireValue.getEncoded()[wireValue.getEncoded().length - 1] & 1));
					if (signalBit == 0){
						otherBytes[otherBytes.length-1] &= 254;
					} else{
						otherBytes[otherBytes.length-1] |= 1;	
					}
					zeroKey = new SecretKeySpec(otherBytes, "");
				}
				allWireValues.put(ungarbledGate.getOutputWireLabels()[0], new SecretKey[] {zeroKey, oneKey});
					
		  	}
		}
	}
}
