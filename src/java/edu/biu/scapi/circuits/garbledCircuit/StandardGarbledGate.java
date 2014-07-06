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

/**
 * This is a standard Garbled Gate. <P>
 * By standard we mean that it is not specialized for specific optimizations. Note though that even optimized circuits may make use 
 * of {@code StandardGarbledGate}. For example, FreeXORGarbledBooleanCircuit, a circuit that is optimized with the
 * Free XOR technique uses {@code StandardGarbledGate}s for all of its non-XOR gates.
 * 
 * @author Steven Goldfeder
 * 
 */
class StandardGarbledGate implements GarbledGate {

	protected MultiKeyEncryptionScheme mes; 					// The {@code MultiKeyEncryptionScheme} that will be used to garbled and compute this Gate.
	
	protected BasicGarbledTablesHolder garbledTablesHolder; 	// Holds the garbled tables.
	
	/* An array containing the indices of the input wires of this gate. 
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
	 * The number of this {@code StandardGarbledGate}. This number is used to order {@code StandardGarbledGate}s in a 
	 * {@link StandardGarbledBooleanCircuitUtil}
	 */
	protected int gateNumber;

	/**
	 * Constructs a garbled gate from an ungarbled gate using the given {@code MultiKeyEncryptionScheme}.
	 * @param ungarbledGate The gate to garble.
	 * @param mes The encryption scheme used to garble this gate.
	 * @param garbledTablesHolder A reference to the garbled tables of the circuit.
   	 */
	StandardGarbledGate(Gate ungarbledGate, MultiKeyEncryptionScheme mes, BasicGarbledTablesHolder garbledTablesHolder){
		//Sets the given parameters.
	    this.mes = mes;
	    inputWireIndices = ungarbledGate.getInputWireIndices();
	    outputWireIndices = ungarbledGate.getOutputWireIndices();
	    gateNumber = ungarbledGate.getGateNumber();
	    this.garbledTablesHolder = garbledTablesHolder;
	}
  
	/**
	 * Creates the garbled table of this gate using the given keys.
	 * @param ungarbledGate The gate to garble.
	 * @param allWireValues Both keys of all the circuit's wires.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */
	void createGarbledTable(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues) throws  IllegalBlockSizeException, PlaintextTooLongException, InvalidKeyException{
	  
		//The number of rows truth table is 2^(number of inputs).
		int numberOfInputs = inputWireIndices.length;
		int numberOfRows = (int) Math.pow(2, numberOfInputs);
		
		//Allocate memory to the garbled table.
		byte[] garbledTable = new byte[numberOfRows * mes.getCipherSize()];
		garbledTablesHolder.toDoubleByteArray()[gateNumber] = garbledTable;
		
		//Calculate the garbled table row by row.
		for (int rowOfTruthTable = 0; rowOfTruthTable < numberOfRows; rowOfTruthTable++) {
			// tweak - what is to be encrypted.
	    	// value - which output wire to xor the encrypted tweak to, 0 or 1.
	    	// permuted position - where to put the result in the output array.
			ByteBuffer tweak = ByteBuffer.allocate(16);
		  	tweak.putInt(gateNumber);
		  	int permutedPosition = 0;
		  	SecretKey[] keysToEncryptOn = new SecretKey[numberOfInputs];
		  	
		  	//This for loop goes through from left to right the input of the given row of the truth table.
		  	for (int i = 0, j = (int) Math.pow(2, numberOfInputs - 1), reverseIndex = numberOfInputs - 1; i < numberOfInputs; i++, j /= 2, reverseIndex--) {
		  	
		  		/* 
		  		 * Truth table inputs are arranged according to binary number values. j is the value that begins as a 1 in the
			   	 * leftmost(most significant bit) of the binary number that is the size of the truth table. Say for example that there are
			   	 * 3 inputs. So the truth table has 3 input columns. j begins as the binary number 100 and we use it to check whether the leftmost bit in
			   	 * the row of the truth table is set. If it is, that means that the input value is a 1.  Otherwise it's a 0. We then divide j by 2 to 
			   	 * obtain the binary number 010 and we use this to determine the value of the inputs in the second column. We then divide by 2 again 
			   	 * to obtain the binary number 001 and use it to determine the value of the inputs in the third column.
			   	 */
        
		  		byte input = (byte) (((rowOfTruthTable & j) == 0) ? 0 : 1);
		  		/*
	    		 * The signal bits tell us the position on the garbled truth table for the given row of an ungarbled truth table.
	    		 * The signal bit of wire i is the last bit of wire i's k0. 
	    		 * See Fairplay — A Secure Two-Party Computation System by Dahlia Malkhi, Noam Nisan1, Benny Pinkas, and Yaron Sella for more on signal bits.
	    		 */
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
		  	
		  	// Set the keys and the tweak of the encryption scheme.
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
  
	@Override
	public void compute(Map<Integer, GarbledWire> computedWires) throws InvalidKeyException, IllegalBlockSizeException, CiphertextTooLongException {
		
		//Calculate the row in the garbled table we need to decrypt.
		int garbledTableIndex = getIndexToDecrypt(computedWires);
		
		// Regenerate the multiSecretKey and the tweak. 
		// Then, reset the tweak and the key to the MultiKeyEncryptionScheme and call its decrypt function.
		SecretKey wireValue = computeGarbledTable(computedWires, garbledTableIndex);
		
		// Create the output wire (s) with the decrypted value.
		int numberOfOutputs = outputWireIndices.length;
		for (int i = 0; i < numberOfOutputs; i++) {
		
			computedWires.put(outputWireIndices[i], new GarbledWire(wireValue));
		}
	}

	/**
	 * Computes the garbled table of this gate.
	 * @param computedWires A Map containing the GarbledWiress that have already been computed and had their values set.
	 * @param garbledTableIndex The index of the row that should be decrypted.
	 * @return the output key.
	 * @throws CiphertextTooLongException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 */
	protected SecretKey computeGarbledTable(Map<Integer, GarbledWire> computedWires, int garbledTableIndex) 
			throws CiphertextTooLongException, InvalidKeyException, IllegalBlockSizeException {
		
		int numberOfInputs = inputWireIndices.length;
		
		SecretKey[] keysToDecryptOn = new SecretKey[numberOfInputs];
		ByteBuffer tweak = ByteBuffer.allocate(16);
		// Put the gate number in the tweak.
		tweak.putInt(gateNumber);
		
		for (int i = 0; i < numberOfInputs; i++) {
			GarbledWire wire = computedWires.get(inputWireIndices[i]);
			keysToDecryptOn[i] = wire.getValueAndSignalBit();
		  
			// Put the signal bits of the input wire values into the tweak.
			tweak.putInt(wire.getSignalBit());
		}
		
		mes.setKey(mes.generateMultiKey(keysToDecryptOn));
		mes.setTweak(tweak.array());
	
		// Decrypt the output value.
		SecretKey wireValue = null;
		try {
			wireValue = new SecretKeySpec(mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
					garbledTableIndex * mes.getCipherSize(), (garbledTableIndex +1)*mes.getCipherSize())),"");
		} catch (KeyNotSetException e) {
			// Should not occur since the key was set.
		} catch (TweakNotSetException e) {
			// Should not occur since the tweak was set.
		}
		return wireValue;
	}
	
	/**
	 * A helper method that computes which index to decrypt based on the signal bits of the input wires.
	 * @param computedWires A {@code Map} containing the input wires and their values. We will use it to obtain the 
	 * signal bits of the values of the input wires in order to determine the correct index to decrypt.
	 * @return the index of the garbled truth table that the input wires' signal bits signal to decrypt.
	 */
	protected int getIndexToDecrypt(Map<Integer, GarbledWire> computedWires) {
		int garbledTableIndex = 0;
		int numberOfInputs = inputWireIndices.length;
		for (int i = numberOfInputs - 1, j = 0; j < numberOfInputs; i--, j++) {
			garbledTableIndex += computedWires.get(inputWireIndices[i]).getSignalBit() * Math.pow(2, j);
		}
		return garbledTableIndex;
	}

	@Override
	public boolean verify(Gate g, Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException, IllegalBlockSizeException, CiphertextTooLongException {
	
		/*
		 *  Step 1: Test to see that these gate's are numbered with the same number. if they're not, then for our purposes they are not
		 * identical. The reason that we treat this as unequal is since in a larger circuit corresponding gates must be identically numbered in 
		 * order for the circuits to be the same.
		 */
		if (gateNumber != g.getGateNumber()) {
			return false;
		}
		
		// Step 2: Check to ensure that the inputWireindices and ouputWireIndices are the same.
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
		
		/*
		 * Step 3: Use allWireValues(i.e. a map that maps each wire to an array that contains its 0-encoding and its 1-encoding) to go through every
		 * combination of input wire values and decrypt the corresponding row of the truth table.
		 * 
		 * Step 4: The decrypted values of the truth table should be(at most) 2 distinct keys--i.e. a 0-encoding for the output wire and a 1-encoding for
		 * the output wire. So, we test whether the arrangement of the garbled truth table is consistent with the ungarbled truth table. 
		 * Specifically, if the ungarbled truth table is 0001, then we test to ensure that the first, second and third entries of the garbled truth 
		 * table are identical and that the fourth entry is different. If this is not true, we return false as the two truth tables are not consistent. 
		 * If this is true, then we add the output wires with the corresponding values to the allWireValues map.
		 * Thus, in our example with the 0001 truth table, the garbled value that corresponds to 0(i.e it appears in the first, second and third positions
		 * of the truth table) is stored as the 0 value for the output wire. The value corresponding to 1 is stored as the 1 value for the output wire.
		 */
		return verifyGarbledTable(g, allWireValues);
	}

	/**
	 * Verifies the garbled table of the gate.
	 * @param g The boolean gate that this gate should be the garbling of.
	 * @param allWireValues A map that contains both keys of all the circuit's wires.
	 * @param numberOfInputs
	 * @return true if the garbled table is valid; false, otherwise.
	 * @throws CiphertextTooLongException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 */
	protected boolean verifyGarbledTable(Gate g, Map<Integer, SecretKey[]> allWireValues)
			throws CiphertextTooLongException, InvalidKeyException,	IllegalBlockSizeException {
		
		int numberOfInputs = inputWireIndices.length;
		
		SecretKey outputZeroValue = null;
		SecretKey outputOneValue = null;
		
		BitSet ungarbledTruthTable = g.getTruthTable();
		
		//There are cases when a gate always output the same key, for example gate that has a 00 garbledTable always outputs the 0-key.
		//In these cases the verifyGarbledTable of the gate will output just the 0-key and the 1-key will remain null.
		//This can cause a NullPointerException if there is a gate that uses this wire as input wire and want to go over all possibilities for input keys.
		//To avoid this exception, if we get a null key, we avoid this possibility for input key.
		boolean keyNotNull = true; 
		// The outer for loop goes through each row of the truth table
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
		    
				//If the key is null, mark this option as no relevant.
				if (currentWireValue == null){
					keyNotNull = false;
					break;
				}
			    // Add the current Wire value to the list of keys to decrypt on. These keys will then be used to construct a multikey.
				keysToDecryptOn[i] = currentWireValue;
			    
				// Look up the signal bit on this wire. This is the last bit of its value.
			    byte signalBit = (byte) ((currentWireValue.getEncoded()[currentWireValue.getEncoded().length - 1] & 1) == 0 ? 0 : 1);
			    
			    // Update the permuted position. For a better understanding on how this works, see the getIndexToDecrypt method in this class.
			    permutedPosition += signalBit * Math.pow(2, reverseIndex);
			    
			    // Add the signal bit of this input wire value to the tweak
			    tweak.putInt(signalBit);
			}
			//If this option is no relevant, do not verify it.
			if (keyNotNull){
				// Set the key and the tweak of the encryption scheme.
				mes.setKey(mes.generateMultiKey(keysToDecryptOn));
				mes.setTweak(tweak.array());
			  
				// Decrypt the output key.
				byte[] pt = null;
				try {
					
					pt = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], permutedPosition * mes.getCipherSize(), (permutedPosition + 1) *mes.getCipherSize()));
				} catch (KeyNotSetException e) {
					// Should not occur since the key has been set.
				} catch (TweakNotSetException e) {
					// Should not occur since the tweak has been set.
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
			keyNotNull = true;
		}
		// Add the output wire to the allWireValues Map.
		for (int w : outputWireIndices) {
			allWireValues.put(w, new SecretKey[] {outputZeroValue, outputOneValue });
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
