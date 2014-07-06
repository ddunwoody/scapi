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
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.CiphertextTooLongException;
import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.exceptions.TweakNotSetException;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;

/**
 * This is a standard Garbled Gate using the row reduction technique. <P>
 * By standard we mean that it is not specialized for specific optimizations. Note though that even optimized circuits may make use 
 * of {@code StandardRowReductionGarbledGate}. For example, FreeXORRowReductionGarbledBooleanCircuit, a circuit that is optimized with the
 * Free XOR technique uses {@code StandardRowReductionGarbledGate}s for all of its non-XOR gates.
 * 
 * @author Steven Goldfeder
 * 
 */
class StandardRowReductionGarbledGate extends StandardGarbledGate{

	private KeyDerivationFunction kdf;
  
	/**
	 * Constructs a garbled gate from an ungarbled gate using the given {@code MultiKeyEncryptionScheme}.
	 * @param ungarbledGate The gate to garble.
	 * @param mes The encryption scheme used to garble this gate.
	 * @param kdf to use in the row reduction technique.
	 * @param garbledTablesHolder A reference to the garbled tables of the circuit.
   	 */
	StandardRowReductionGarbledGate(Gate ungarbledGate, MultiKeyEncryptionScheme mes, KeyDerivationFunction kdf, BasicGarbledTablesHolder garbledTablesHolder){
		super(ungarbledGate, mes, garbledTablesHolder);
		this.kdf = kdf;;
	}
  
	/**
	 * Creates the garbled table of this gate using the row reduction technique. <p>
	 * Meaning that the last row is not saved and will be calculated when the compute function will be called by the kdf.
	 */
	@Override
	void createGarbledTable(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues) throws  IllegalBlockSizeException, PlaintextTooLongException, InvalidKeyException{
		//The number of rows is 2^numberOfInputs - 1. The last row will be calculated by the row reduction technique.
		int numberOfInputs = inputWireIndices.length;
		int numberOfRows = (int) Math.pow(2, numberOfInputs)-1;
		
		//Allocate memory to the garbled table.
		byte[] garbledTable = new byte[numberOfRows * mes.getCipherSize()];
		garbledTablesHolder.toDoubleByteArray()[gateNumber] = garbledTable;
		
		//Calculate the garbled table row by row.
		for (int rowOfTruthTable = 0; rowOfTruthTable <= numberOfRows; rowOfTruthTable++) {
		  	ByteBuffer tweak = ByteBuffer.allocate(16);
		  	tweak.putInt(gateNumber);
		  	
		  	// Permuted position will be the index of the garbled truth table corresponding to rowOfTruthTable.
		  	int permutedPosition = 0;
		  	SecretKey[] keysToEncryptOn = new SecretKey[numberOfInputs];
		  	
		  	//This for loop goes through from left to right the input of the given row of the truth table.
		  	for (int i = 0, j = (int) Math.pow(2, numberOfInputs - 1), reverseIndex = numberOfInputs - 1; i < numberOfInputs; i++, j /= 2, reverseIndex--) {
		  	
		  		/* Truth table inputs are arranged according to binary number values. j is the value that begins as a 1 in the
			   	 * leftmost(most significant bit) of the binary number that is the size of the truth table. Say for example that there are
			   	 * 3 inputs. So the truth table has 3 input columns. j begins as the binary number 100 and we use it to check whether the leftmost bit in
			   	 * the row of the truth table is set. If it is, that means that the input value is a 1.  Otherwise it's a 0. We then divide j by 2 to obtain the binary
			   	 * number 010 and we use this to determine the value of the inputs in the second column. We then divide by 2 again to obtain the 
			   	 * binary number 001 and use it to determine the value of the inputs in the third column
			   	 */
        
		  		int input = (((rowOfTruthTable & j) == 0) ? 0 : 1);
		  		
		  		//signal bit is the last bit of k0.
		  		byte[] k0 = allWireValues.get(inputWireIndices[i])[0].getEncoded();
		  		byte signalBit =  (byte) (k0[k0.length-1] & 1);
		  		
		  		
		  		// Update the permuted position. For a better understanding on how this works, see the getIndexToDecrypt method in this class.
		  		permutedPosition += (input ^ signalBit) * (Math.pow(2, reverseIndex));
		  		
		  		// Add the current Wire value to the list of keys to encrypt on. These keys will then be used to construct a multikey.
		  		keysToEncryptOn[i] = allWireValues.get(inputWireIndices[i])[input];
		  		
		  		/*
		  		 * We add the signalBit that is placed on the end of the wire's value which is given by input XOR signalBit (i.e. the random bit for the
		  		 * wire). Again, to clarify we use the term signal bit to mean both the random but assigned to each wire as well as the bit that is
		  		 * associated with each of the wire's 2 values. The latter value is obtained by XORing the signal bit of the wire with the actual value
		  		 * that the garbled value is encoding. So, for example if the signal bit for the wire is 0. Then the 0-encoded value will have 0 XOR 
		  		 * 0 = 0 as its signal bit. The 1-encoded value will have 0 XOR 1 = 1 as its signal bit.
		  		 */
		  		tweak.putInt(input ^ signalBit);
		  	}
		  	
		  	//In row reduction technique we compute all rows except the last one. The last row will be calculated by the KDF.
		  	if (permutedPosition != numberOfRows){ 
		  		//Set the keys and the tweak of the encryption scheme.
		  		mes.setKey(mes.generateMultiKey(keysToEncryptOn));
			  	mes.setTweak(tweak.array());
			  	
			  	// Get the output value that should be garbled.
			  	int value = (ungarbledGate.getTruthTable().get(rowOfTruthTable) == true) ? 1: 0;
	      
			  	// Encrypt the output key and put the ciphertext in the garbled table.
			  	try {
					System.arraycopy(mes.encrypt(allWireValues.get(outputWireIndices[0])[value].getEncoded()) , 0, garbledTable, permutedPosition*mes.getCipherSize(), mes.getCipherSize());
				} catch (KeyNotSetException e) {
					// Should not occur since the encryption has a key.
				} catch (TweakNotSetException e) {
					// Should not occur since the encryption has a tweak.			
				}
		  	}
		}
	}
  
	@Override
	public void compute(Map<Integer, GarbledWire> computedWires) throws InvalidKeyException, IllegalBlockSizeException, CiphertextTooLongException {
		//Calculate the row in the garbled table we need to decrypt.
		int garbledTableIndex = getIndexToDecrypt(computedWires);
		SecretKey wireValue = null;
		int numberOfInputs = inputWireIndices.length;
		
		//In case of the last row, calculate the output key by the KDF.
		//The number of rows is 2^numberOfInputs - 1. The last row will be calculated by the row reduction technique.
		int numberOfRows = (int) Math.pow(2, numberOfInputs)-1;
		if (garbledTableIndex == numberOfRows){
			
			ByteBuffer kdfBytes = ByteBuffer.allocate(mes.getCipherSize()*numberOfInputs +16);
			for (int i = 0; i < numberOfInputs; i++) {
				kdfBytes.put(computedWires.get(inputWireIndices[i]).getValueAndSignalBit().getEncoded());
			}
			kdfBytes.putInt(gateNumber);
			for (int i = 0; i < numberOfInputs; i++) {
				kdfBytes.putInt(computedWires.get(inputWireIndices[i]).getSignalBit());
			}
			wireValue = kdf.deriveKey(kdfBytes.array(), 0, mes.getCipherSize()*numberOfInputs +16, mes.getCipherSize());
			
		}else {
		
			// Regenerate the multiSecretKey and the tweak. 
			// Then, reset the tweak and the key to the MultiKeyEncryptionScheme and call its decrypt function.
			wireValue = computeGarbledTable(computedWires, garbledTableIndex);
		}
		int numberOfOutputs = outputWireIndices.length;
		for (int i = 0; i < numberOfOutputs; i++) {
		
			computedWires.put(outputWireIndices[i], new GarbledWire(wireValue));
		}
	}

	@Override
	protected boolean verifyGarbledTable(Gate g, Map<Integer, SecretKey[]> allWireValues)
			throws CiphertextTooLongException, InvalidKeyException,	IllegalBlockSizeException {
		int numberOfInputs = inputWireIndices.length;
		
		BitSet ungarbledTruthTable = g.getTruthTable();
		
		SecretKey outputZeroValue = null;
		SecretKey outputOneValue = null;
		
		// The outer for loop goes through each row of the truth table.
		for (int rowOfTruthTable = 0; rowOfTruthTable < Math.pow(2, numberOfInputs); rowOfTruthTable++) {
		
			// Permuted position will be the index of the garbled truth table corresponding to rowOfTruthTable.
			int permutedPosition = 0;
			ByteBuffer tweak = ByteBuffer.allocate(16);
			tweak.putInt(gateNumber);
			SecretKey[] keysToDecryptOn = new SecretKey[numberOfInputs];
			
			// This for loop goes through from left to right the input of the given row of the truth table.
			for (int i = 0, j = (int) Math.pow(2, numberOfInputs - 1), reverseIndex = numberOfInputs - 1; i < numberOfInputs; i++, j /= 2, reverseIndex--) {
				int input = ((rowOfTruthTable & j) == 0) ? 0 : 1;
				SecretKey currentWireValue = allWireValues.get(inputWireIndices[i])[input];
		    
			    // Add the current Wire value to the list of keys to decrypt on. These keys will then be used to construct a multikey.
				keysToDecryptOn[i] = currentWireValue;
			    
				// Look up the signal bit on this wire. This is the last bit of its value.
			    int signalBit = (currentWireValue.getEncoded()[currentWireValue.getEncoded().length - 1] & 1) == 0 ? 0 : 1;
			    
			    // Update the permuted position. For a better understanding on how this works, see the getIndexToDecrypt method in this class.
			    permutedPosition += signalBit * Math.pow(2, reverseIndex);
			    
			    // Add the signal bit of this input wire value to the tweak.
			    tweak.putInt(signalBit);
			}
			byte[] pt = null;
			//In case other than the last row, verify the row by the encryption scheme.
			int numberOfRows = (int) Math.pow(2, numberOfInputs)-1;
			if (permutedPosition != numberOfRows){
				 mes.setKey(mes.generateMultiKey(keysToDecryptOn));
				 mes.setTweak(tweak.array());
			  
				 try {
					 pt = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], permutedPosition * mes.getCipherSize(), (permutedPosition + 1) *mes.getCipherSize()));
				 } catch (KeyNotSetException e) {
					 // Should not occur since the key has been set.
				 } catch (TweakNotSetException e) {
					 // Should not occur since the tweak has been set.
				 }
				 
			//In case of the last row, verify the row by the KDF.
			} else{
				//Allocate a byte array to hold the bytes for the KDF.
		  		ByteBuffer kdfBytes = ByteBuffer.allocate(mes.getCipherSize()*numberOfInputs +16);
		  		
		  		//The input for the kdf should be the concatenation of input keys, gate number and input keys' signal bits.
		  		SecretKey[] keys = new SecretKey[numberOfInputs];
		  		for (int i=0; i<numberOfInputs; i++){
		  			//Get the index of the input key.
		  			int wireKeyIndex = ((rowOfTruthTable & (numberOfInputs - i)) == 0) ? 0 : 1;
		  			//Put each input key in the kdf array.
		  			keys[i] = allWireValues.get(inputWireIndices[i])[wireKeyIndex];
		  			kdfBytes.put(keys[i].getEncoded());
		  		}
		  		//Put gate number in the kdf array.
				kdfBytes.putInt(gateNumber);
				//Put each signal bit in the kdf array.
				for (int i=0; i<numberOfInputs; i++){
					kdfBytes.putInt((keys[i].getEncoded()[keys[i].getEncoded().length - 1] & 1) == 0 ? 0 : 1);
				}
				
				//Compute the KDF.
				pt = kdf.deriveKey(kdfBytes.array(), 0, mes.getCipherSize()*numberOfInputs +16, mes.getCipherSize()).getEncoded();
					
			}
			
			// Check to see that rows of the truth table with the same ungarbled value have the same garbled value as well.
			if (ungarbledTruthTable.get(rowOfTruthTable) == true) {// i.e this bit is set
				
				// This is the first time we face k1, create it.
				if (outputOneValue == null) {
					outputOneValue = new SecretKeySpec(pt, "");
				// K1 has already been created, check that it is equal to the current value.
				} else{
					byte[] oneValueBytes = outputOneValue.getEncoded();
					for (int byteArrayIndex = 0; byteArrayIndex < pt.length; byteArrayIndex++) {
						if (pt[byteArrayIndex] != oneValueBytes[byteArrayIndex]) {
							return false;
						}
					}
			 	} 
			} else { //Bit is not set.
				// This is the first time we face k0, create it.
				if (outputZeroValue == null) {
					outputZeroValue = new SecretKeySpec(pt, "");
				// K0 has already been created, check that it is equal to the current value.
				} else {
					byte[] zeroValueBytes = outputZeroValue.getEncoded();
					for (int byteArrayIndex = 0; byteArrayIndex < pt.length; byteArrayIndex++) {
						if (pt[byteArrayIndex] != zeroValueBytes[byteArrayIndex]) {
							return false;
						}
					}	
				}
			}
		}
		//Add the output wire to the allWireValues Map.
		for (int w : outputWireIndices) {
			allWireValues.put(w, new SecretKey[] {outputZeroValue, outputOneValue });
		}
		return true;
	}
}
