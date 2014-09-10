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
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.kdf.bc.BcKdfISO18033;

/**
 * The {FreeXORRowReductionGarbledBooleanCircuit} class is a utility class that computes the functionalities regarding Free XOR Garbled Boolean Circuit 
 * using the row reduction technique.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class FreeXORRowReductionGarbledBooleanCircuitUtil extends FreeXORGarbledBooleanCircuitUtil {

	private KeyDerivationFunction kdf;
	
	/**
	 * Sets the given MultiKeyEncryptionScheme and kdf.
	 * @param mes
	 * @param kdf
	 */
	FreeXORRowReductionGarbledBooleanCircuitUtil(MultiKeyEncryptionScheme mes, KeyDerivationFunction kdf) {
		super(mes);
		this.kdf = kdf;
	}
	
	/**
	 * Default constructor. Uses AESFixedKeyMultiKeyEncryption object and .
	 */
	FreeXORRowReductionGarbledBooleanCircuitUtil() {
		super();
		try {
			this.kdf = new BcKdfISO18033("SHA-224");
		} catch (FactoriesException e) {
			// Should not occur since the hash name is valid.
		}
	}
	
	@Override
	protected GarbledGate createStandardGate(Gate ungarbledGate, BasicGarbledTablesHolder garbledTablesHolder) {
		
		//The last gate that was added in order to allow sampling keys out of given output keys should not use the row reduction technique.
		return new StandardRowReductionGarbledGate(ungarbledGate, mes, kdf, garbledTablesHolder);
	}
	
	/**
	 * Generates keys for a standard gate in the row reduction technique.
	 * @param zeroValueBytes this value is ignored since the row reduction technique calculates both values from the gate's input keys.
	 */
	protected void generateStandardValues(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues, byte[] globalKeyOffset, byte[] zeroValueBytes) {
		//The last gate that was added in order to allow sampling keys out of given output keys should not use the row reduction technique.
		int[] indices = ungarbledGate.getInputWireIndices();
		int numberOfInputs = indices.length;
		//number of rows is 2^numberOfInputs - 1. The last row will be calculated by the row reduction technique.
		int numberOfRows = (int) Math.pow(2, numberOfInputs)-1;
		
		//Find the line that we do not save in the table and we use the KDF to find the value of the output key.
		for (int rowOfTruthTable = 0; (rowOfTruthTable <= numberOfRows) && !(allWireValues.containsKey(ungarbledGate.getOutputWireIndices()[0])); rowOfTruthTable++) {
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
		  		
		  		//signal bit is the last bit of k0.
		  		byte[] k0 = allWireValues.get(indices[i])[0].getEncoded();
		  		byte signalBit =  (byte) (k0[k0.length-1] & 1);
		  		
		  		permutedPosition += (input ^ signalBit) * (Math.pow(2, reverseIndex));		
		  	
		  	}
		  	
		  	//This is the row that we do not save in the table but calculate the value via KDF.
		  	if (permutedPosition == numberOfRows){
		  		//Allocate a byte array to hold the bytes for the KDF.
		  		ByteBuffer kdfBytes = ByteBuffer.allocate(mes.getCipherSize()*numberOfInputs +16);
		  		
		  		//The input for the kdf should be the concatenation of input keys, gate number and input keys' signal bits.
		  		SecretKey[] keys = new SecretKey[numberOfInputs];
		  		for (int i=0; i<numberOfInputs; i++){
		  			//Get the index of the input key.
		  			int wireKeyIndex = ((rowOfTruthTable & (numberOfInputs - i)) == 0) ? 0 : 1;
		  			//Put each input key in the kdf array.
		  			keys[i] = allWireValues.get(indices[i])[wireKeyIndex];
		  			kdfBytes.put(keys[i].getEncoded());
		  		}
		  		//Put gate number in the kdf array.
				kdfBytes.putInt(ungarbledGate.getGateNumber());
				//Put each signal bit in the kdf array.
				for (int i=0; i<numberOfInputs; i++){
					kdfBytes.putInt((keys[i].getEncoded()[keys[i].getEncoded().length - 1] & 1) == 0 ? 0 : 1);
				}
				
				//Compute the KDF.
				SecretKey wireValue = kdf.deriveKey(kdfBytes.array(), 0, mes.getCipherSize()*numberOfInputs +16, mes.getCipherSize());
				
				byte[] kdfResultBytes = wireValue.getEncoded();
				//Calculate the other value by xoring the kdf result with the globalKeyOffset
				byte[] otherBytes = new byte[mes.getCipherSize()];
				for (int i = 0; i < zeroValueBytes.length; i++) {
					otherBytes[i] = (byte) (kdfResultBytes[i] ^ globalKeyOffset[i]);
				}
				
				//Now we have both values, calculate the signal bit.
				boolean output = ungarbledGate.getTruthTable().get(rowOfTruthTable);
				SecretKey zeroKey, oneKey;
				if (output == false){
					zeroKey = wireValue;
					oneKey = new SecretKeySpec(otherBytes, "");
				} else {
					oneKey = wireValue;
					zeroKey = new SecretKeySpec(otherBytes, "");
				}
				
				//Put k0, k1 in the map.
				allWireValues.put(ungarbledGate.getOutputWireIndices()[0], new SecretKey[] {zeroKey, oneKey});
					
		  	}
		}
		 
	}
	
	
}
