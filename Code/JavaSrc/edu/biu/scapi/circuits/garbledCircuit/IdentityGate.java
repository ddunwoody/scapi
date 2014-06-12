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
import java.security.SecureRandom;
import java.util.Arrays;
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
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;

/**
 * The identity gates are used in the extended circuit.
 * There are cases when the user want to set the input and/or output keys (which are the garbled values of 0/1 for each wire).
 * In that cases, the extended circuit adds to the composed circuit identity gates for each input and output wires.
 * This way, if the user gave input keys, there are input identity gates for each input wire w, with input wire indexed -(w+1) and output wire w.
 * If the user gave output keys, there are output identity gates for each output wire w, with input wire indexed w and output wire -(w+1).
 * Notice that for the composed circuit the input and output wires remain the same.
 * 
 * The identity gates maps the 0 input key to the 0 output key, and the 1 input key to the 1 output key.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class IdentityGate implements GarbledGate{

	private MultiKeyEncryptionScheme mes; 	// The {@code MultiKeyEncryptionScheme} that will be used to garbled and compute this Gate.
	private PseudorandomGenerator prg;		//The prg to use in case of garbling using a seed.
	
	private BasicGarbledTablesHolder garbledTablesHolder; 	//Holds the garbled tables.
	
	private int inputWireIndex;				//The index of the input Wire of this gate. 
	private int outputWireIndex;			//The index of the output Wire of this gate. 
	  
	//The number of this {@code IdentityGate}. This number is used to order {@code IdentityGate}s in a {@link GarbledBooleanCircuitExtended}
	private int gateNumber;
	
	/**
	 * Constructs an identity gate using the given {@code MultiKeyEncryptionScheme}.
	 * This constructor should be used in case the garbling is going to be done using the enryption scheme.
	 * In case of the garbling is going to be done using a prg and seed, use the constructor that accepts a prg.
	 * @param gateNumber The gate's index.
	 * @param inputWireIndex The gate's input wire index.
	 * @param outputWireIndex The gate's output wire index.
	 * @param mes The encryption scheme used to garble this gate.
	 * @param garbledTablesHolder A reference to the garbled tables of the circuit.
   	 */
	IdentityGate(int gateNumber, int inputWireIndex, int outputWireIndex, MultiKeyEncryptionScheme mes, BasicGarbledTablesHolder garbledTablesHolder){
		//Sets the given parameters.
	    this.mes = mes;
	    this.inputWireIndex = inputWireIndex;
		this.outputWireIndex = outputWireIndex;
		this.gateNumber = gateNumber;
	    this.garbledTablesHolder = garbledTablesHolder;
	}
	
	/**
	 * Constructs an identity gate using the given {@code MultiKeyEncryptionScheme} and {@link PseudorandomGenerator}.
	 * This constructor should be used in case the garbling is going to be done using using a prg and seed.
	 * In case of the garbling is going to be done using the enryption scheme, use the other constructor.
	 * @param gateNumber The gate's index.
	 * @param inputWireIndex The gate's input wire index.
	 * @param outputWireIndex The gate's output wire index.
	 * @param mes The encryption scheme used to garble this gate.
	 * @param garbledTablesHolder A reference to the garbled tables of the circuit.
	 * @param prg The {@link PseudorandomGenerator} object to use during garbling.
   	 */
	IdentityGate(int gateNumber, int inputWireIndex, int outputWireIndex, MultiKeyEncryptionScheme mes, BasicGarbledTablesHolder garbledTablesHolder, PseudorandomGenerator prg){
		this(gateNumber, inputWireIndex, outputWireIndex, mes, garbledTablesHolder);
		this.prg = prg;
	}
  
	
	/**
	 * Creates the garbled table of this gate using the given keys.
	 * @param allWireValues Both keys of all the circuit's wires.
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws PlaintextTooLongException
	 */
	void createGarbledTable(Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException, IllegalBlockSizeException, PlaintextTooLongException {
	  
		/*
		 * Identity gate has one input wire and one output wire.
		 * Assume input wire's keys are k0, k1 and output wire's keys k0', k1'.
		 * The garbled table is as follows:
		 * 
		 * Enc(k0')Enc(0^cipherSize) using k0 - row number i (i = 0 ,1)
		 * Enc(k1')Enc(0^cipherSize) using k1 - row number 1-i
		 * 
		 */
		
		//Allocate memory to the garbled table. Two rows when each row contain two encryptions.
		byte[] garbledTable = new byte[2 * mes.getCipherSize() * 2];
		//Set the created table to the holder.
		garbledTablesHolder.toDoubleByteArray()[gateNumber] = garbledTable;
		
		//The order of the rows should be random.
		//In case of garbling using a seed, the random choose is done using the prg.
	  	int position;
	  	if (prg != null){
	  		byte[] out = new byte[1];
	  		prg.getPRGBytes(out, 0, 1);
	  		position = ((out[0] == 0)? 0 : 1);
	  	} else{
	  		position = new SecureRandom().nextBoolean() == true? 1 : 0;
	  		
	  	}
		  	
		  	
	  	SecretKey keyToEncryptOn;
	  	byte[] zeros = new byte[mes.getCipherSize()];
	  	
	  	//Tweak is required by some encryption schemes.
	  	ByteBuffer tweak = ByteBuffer.allocate(16);
		tweak.putInt(gateNumber);
		
		//Set each input key in the encryption scheme, encrypt the corresponding output key and then encrypt zeros.
	  	for(int i=0; i<2; i++){
	  		keyToEncryptOn = allWireValues.get(inputWireIndex)[i];
	  		
	  		// Set the keys and the tweak of the encryption scheme.
		  	mes.setKey(mes.generateMultiKey(keyToEncryptOn));
		  	mes.setTweak(tweak.array());
		  	byte[] keyPlaintext = allWireValues.get(outputWireIndex)[i].getEncoded();
		  	
		  	// Encrypt the output key and zeros and put the ciphertexts in the garbled table.
		  	try {
				System.arraycopy(mes.encrypt(keyPlaintext), 0, garbledTable, position*mes.getCipherSize()*2, mes.getCipherSize());
				System.arraycopy(mes.encrypt(zeros), 0, garbledTable, position*mes.getCipherSize()*2 + mes.getCipherSize(), mes.getCipherSize());
				
			} catch (KeyNotSetException e) {
				// Should not occur since the encryption has a key.
			} catch (TweakNotSetException e) {
				// Should not occur since the encryption has a tweak.			
			}
		  	//flip row for next round.
		  	position = 1-position;
	  	}	  	
	}
	
	@Override
	public void compute(Map<Integer, GarbledWire> computedWires) throws InvalidKeyException, IllegalBlockSizeException,
			CiphertextTooLongException {
		/*
		 * Identity gate has one input wire and one output wire.
		 * Assume input wire's keys are k0, k1 and output wire's keys k0', k1'.
		 * 
		 * The garbled table is as follows:
		 * 
		 * Enc(k0')Enc(0^cipherSize) using k0 - row number i (i = 0 ,1)
		 * Enc(k1')Enc(0^cipherSize) using k1 - row number 1-i
		 * 
		 * When computing, the input wire contains one of k0 or k1.
		 * We need to find which row to decrypt.
		 * The algorithm:
		 * 
		 * 1. Decrypt part two of the first row, 
		 * 2. If the result is 0^cipherSize, decrypt the first part of the first row. This is the output wire of the gate.
		 * 3. Else, decrypt part two of the second row, if the result is 0^cipherSize, decrypt the first part of the second row. This is the output wire of the gate.
		 * 4. Else, throw exception.
		 */
		
		//Get the input garlbed value.
		GarbledWire wire = computedWires.get(inputWireIndex);
		SecretKey keyToDecryptOn = wire.getValueAndSignalBit();
		  
		//Set the key and tweak to the encryption scheme.
		mes.setKey(mes.generateMultiKey(keyToDecryptOn));
		ByteBuffer tweak = ByteBuffer.allocate(16);
		tweak.putInt(gateNumber);
		mes.setTweak(tweak.array());
		
		byte[] wireValue = null;
		
		try {
			// Find which row has the encryption of zeros using the given key. 
			int rowI = -1;
			for (int i=0; i<2 && rowI<0; i++){
				//Decrypt the zeros part.
				byte[] validateZeros = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
					i*mes.getCipherSize()*2 + mes.getCipherSize(), i*mes.getCipherSize()*2 + 2*mes.getCipherSize()));
				//Check if the result are zeros.
				boolean validateRow = validateRow(validateZeros);
				//In case of zeros, fix the row index.
				if (validateRow){
					rowI = i;
				}
			}
			
			//If both rows do not contain encryption of zeros according the given key, throw exception.
			if (rowI == -1){
				throw new IllegalArgumentException("input wire value is invalid");	
			}
			
			//Decrypt the first part of the chosen row.
			wireValue = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
							rowI*mes.getCipherSize()*2, rowI*mes.getCipherSize()*2+mes.getCipherSize()));
				
		} catch (KeyNotSetException e) {
			// Should not occur since the key was set.
		} catch (TweakNotSetException e) {
			// Should not occur since the tweak was set.
		}
		
		SecretKey outputValue = new SecretKeySpec(wireValue, "");
		// Create the output wire with the decrypted value.
		computedWires.put(outputWireIndex, new GarbledWire(outputValue));	
	}

	/**
	 * Check that the given byte array contains 0^cipherSize.
	 * @param validateZeros That should be verified.
	 * @return true if the given byte array contains 0^cipherSize; False, otherwise.
	 */
	private boolean validateRow(byte[] validateZeros) {
		boolean validateRow = true;
		//Check that th elength is correct.
		if (validateZeros.length != mes.getCipherSize()){
			validateRow = false;
		}else{
			//Check that each byte is zero.
			for (int i=0; i<mes.getCipherSize(); i++){
				if (validateZeros[i] != 0)
					validateRow = false;
			}
		}
		return validateRow;
	}

	@Override
	public boolean verify(Gate g, Map<Integer, SecretKey[]> allWireValues) 	throws InvalidKeyException, IllegalBlockSizeException,
			CiphertextTooLongException {
		/*
		 *  Step 1: Test to see that these gate's are numbered with the same number. if they're not, then for our purposes they are not
		 * identical. The reason that we treat this as unequal is since in a larger circuit corresponding gates must be identically numbered in 
		 * order for the circuits to be the same.
		 */
		if (gateNumber != g.getGateNumber()) {
			return false;
		}
		
		// Step 2: Check to ensure that the inputWireIndex and ouputWireIndex are the same.
		int[] ungarbledInputWireIndices = g.getInputWireIndices();
		int[] ungarbledOutputWireIndices = g.getOutputWireIndices();
		if (1 != ungarbledInputWireIndices.length || 1 != ungarbledOutputWireIndices.length) {
			return false;
		}
		if (inputWireIndex != ungarbledInputWireIndices[0]) {
			    return false;
		}
		if (outputWireIndex != ungarbledOutputWireIndices[0]) {
			    return false;
		}
		
		/*
		 * Step 3: The decrypted values of the truth table should be(at most) 2 distinct keys--i.e. a 0-encoding for the output wire and a 1-encoding for
		 * the output wire. So, we test that each input key can translate one and only one row in the garbled table. 
		 * Also, check that the row that k0 and k1 decrypt are distinct. 
		 */
		return verifyGarbledTable(allWireValues);
	}
	
	/**
	 * Verifies the garbled table of the gate.
	 * The decrypted values of the truth table should be(at most) 2 distinct keys--i.e. a 0-encoding for the output wire and a 1-encoding for
	 * the output wire. We test that each input key can translate one and only one row in the garbled table. 
	 * Also, check that the row that k0 and k1 decrypt are distinct.
	 * @param allWireValues A map that contains both keys of all the circuit's wires.
	 * @return true if the garbled table is valid; false, otherwise.
	 * @throws CiphertextTooLongException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 */
	protected boolean verifyGarbledTable(Map<Integer, SecretKey[]> allWireValues)
			throws CiphertextTooLongException, InvalidKeyException,	IllegalBlockSizeException {
		
		SecretKey outputZeroValue = null;
		SecretKey outputOneValue = null;
		
		//Set the tweak.
		ByteBuffer tweak = ByteBuffer.allocate(16);
		tweak.putInt(gateNumber);
		mes.setTweak(tweak.array());
		
		
		byte[] validateZeros;
		boolean validateRow;
		int rowI = -1;
		try {
			//Get k0, set it to the encryption scheme.
			SecretKey k0 = allWireValues.get(inputWireIndex)[0];
			mes.setKey(mes.generateMultiKey(k0));
			
			//Check that k0 decrypts one and only one row.
			for (int i=0; i<2 && rowI<0; i++){
				//Decrypt part two of the row.
				validateZeros = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
					i*mes.getCipherSize()*2 + mes.getCipherSize(), i*mes.getCipherSize()*2 + 2*mes.getCipherSize()));
				//Check the output.
				validateRow = validateRow(validateZeros);
				//If the output contains zeros, and no row was decrypted yet, save the row index.
				//If the output contains zeros, and there is a row that was decrypted yet, return false. (k0 can decrypt more than one row.)
				if (validateRow == true){
					if (rowI>0){
						return false;
					} else{
						rowI = i;
					}
				}
			}
			//If k0 can not decrypt any row, return false.
			if (rowI == -1){
				return false;
			}
			
			//k0 can decrypt one and only one row, decrypt the first part of that row to get k0'.
			byte[] outputValue = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
							rowI*mes.getCipherSize()*2, rowI*mes.getCipherSize()*2+mes.getCipherSize()));
			outputZeroValue = new SecretKeySpec(outputValue, "");
			
			//Get k1, set it to the encryption scheme.
			SecretKey k1 = allWireValues.get(inputWireIndex)[1];
			mes.setKey(mes.generateMultiKey(k1));
			
			//Flip row.
			rowI = -1;
			//Check that k1 decrypts one and only one row.
			for (int i=0; i<2 && rowI<0; i++){
				//Decrypt part two of the row.
				validateZeros = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
					i*mes.getCipherSize()*2 + mes.getCipherSize(), i*mes.getCipherSize()*2 + 2*mes.getCipherSize()));
				//Check the output.
				validateRow = validateRow(validateZeros);
				//If the output contains zeros, and no row was decrypted yet, save the row index.
				//If the output contains zeros, and there is a row that was decrypted yet, return false. (k1 can decrypt more than one row.)
				if (validateRow == true && rowI<0){
					rowI = i;
				}
			}
			//If k1 can not decrypt any row, return false.
			if (rowI == -1){
				return false;
			}
			//k1 can decrypt one and only one row, decrypt the first part of that row to get k1'.
			outputValue = mes.decrypt(Arrays.copyOfRange(garbledTablesHolder.toDoubleByteArray()[gateNumber], 
							rowI*mes.getCipherSize()*2, rowI*mes.getCipherSize()*2+mes.getCipherSize()));
				
			outputOneValue = new SecretKeySpec(outputValue, "");
			
		} catch (KeyNotSetException e) {
			// Should not occur since the key was set.
		} catch (TweakNotSetException e) {
			// Should not occur since the tweak was set.
		}
		
		//Put the calculated output values as both values of the output wire.
		allWireValues.put(outputWireIndex, new SecretKey[] {outputZeroValue, outputOneValue });
		
		return true;
	}

	@Override
	public int[] getInputWireIndices() {
		
		int[] inputIndices = new int[1];
		inputIndices[0] = inputWireIndex;
		return inputIndices;
	}

	@Override
	public int[] getOutputWireIndices() {
		
		int[] outputIndices = new int[1];
		outputIndices[0] = outputWireIndex;
		return outputIndices;
	}

}
