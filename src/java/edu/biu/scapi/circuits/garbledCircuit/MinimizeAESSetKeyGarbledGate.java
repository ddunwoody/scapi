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
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.circuits.circuit.Gate;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;

/**
 * {@link MinimizeAESSetKeyGarbledGate} takes on the role of both a garbled gate and an {@code AES128MultiKeyEncryption} in order to encrypt the
 * Gate while minimizing the number of AES setKey operations. <p>
 * See {@code MinimizeAESSetKeyGarbledBooleanCircuitUtil} for a full discussion of the reason for doing this as well as our design decisions.<p>
 * Note that currently only the constructor and not the verify method minimizes AES set key calls.
 *
 * @author Steven Goldfeder
 * 
 */
class MinimizeAESSetKeyGarbledGate extends StandardGarbledGate {

	private PseudorandomFunction aes;
  
	/**
	 * Constructs a MinimizeAESSetKeyGarbledGate from an ungarbled gate using the given aes and {@code MultiKeyEncryptionScheme}.
	 * @param ungarbledGate The gate to garbled.
	 * @param mes The encryption scheme used to garbled this gate.
	 * @param aes The AES object to use to garbled this gate.
	 * @param garbledTablesHolder A reference to the garbled tables of the circuit.
   	 */
	MinimizeAESSetKeyGarbledGate(Gate ungarbledGate, MultiKeyEncryptionScheme mes, PseudorandomFunction aes, BasicGarbledTablesHolder garbledTablesHolder){
		
		super(ungarbledGate, mes, garbledTablesHolder);
		this.aes = aes;
	}	
   
	@Override
	void createGarbledTable(Gate ungarbledGate, Map<Integer, SecretKey[]> allWireValues) throws InvalidKeyException, IllegalBlockSizeException {
		
		//The number of rows truth table is 2^(number of inputs).
		int numberOfInputs = inputWireIndices.length;
		int numberOfRows = (int) Math.pow(2, numberOfInputs);
		
		//Allocate memory to the garbled table.
		byte[] garbledTable = new byte[numberOfRows * mes.getCipherSize()];
		garbledTablesHolder.toDoubleByteArray()[gateNumber] = garbledTable;
    
	    /*
	     * Rather than encrypt right away as we do in StandardGarbledGate, here we create arrays to hold the data. 
	     * This way, we only encrypt once we have all of the data ready, and thus we can minimize the number of times we set the key for AES.
	     */
	    byte[][] tweaksToEncrypt = new byte[numberOfRows][];
	    byte[][] outputValuesToEncrypt = new byte[numberOfRows][];
	    int[][] valuesToEncryptOn = new int[numberOfRows][];

	    // An array where we put the output values.
	    byte[][] outputValues = new byte[numberOfRows][aes.getBlockSize()];

	    //Calculate the garbled table row by row.
	    for (int rowOfTruthTable = 0; rowOfTruthTable < numberOfRows; rowOfTruthTable++) {
	    	int[] temp = new int[numberOfInputs];
	    	
	    	// tweak - what is to be encrypted.
	    	// value - which output wire to xor the encrypted tweak to, 0 or 1.
	    	// permuted position - where to put the result in the output array.
	    	ByteBuffer tweak = ByteBuffer.allocate(aes.getBlockSize());
	    	tweak.putInt(gateNumber);
	    	byte permutedPosition = 0;

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
	    		 * See Fairplay — A Secure Two-Party Computation System by Dahlia Malkhi, Noam Nisan1, Benny Pinkas, and Yaron Sella for more on signal bits.
	    		 */
	    		byte[] k0 = allWireValues.get(inputWireIndices[i])[0].getEncoded();
		  		byte signalBit =  (byte) (k0[k0.length-1] & 1);

	    		// Update the permuted position. For a better understanding on how this works, see the getIndexToDecrypt method in this class.
		        permutedPosition += (input ^ signalBit) * (Math.pow(2, reverseIndex));
		        temp[i] = input;

		        /*
		  		 * We add the signalBit that is placed on the end of the wire's value which is given by input XOR signalBit (i.e. the random bit for the
		  		 * wire). Again, to clarify we use the term signal bit to mean both the random but assigned to each wire as well as the bit that is
		  		 * associated with each of the wire's 2 values. The latter value is obtained by XORing the signal bit of the wire with the actual value
		  		 * that the garbled value is encoding. So, for example if the signal bit for the wire is 0. Then the 0-encoded value will have 0 XOR 
		  		 * 0 = 0 as its signal bit. The 1-encoded value will have 0 XOR 1 = 1 as its signal bit.
		  		 */
		        tweak.putInt(input ^ signalBit);
	    	}
	    	
	    	//Save the calculated values to use later, all at once.
	    	valuesToEncryptOn[permutedPosition] = temp;
	    	tweaksToEncrypt[permutedPosition] = tweak.array();
	    	int value = (ungarbledGate.getTruthTable().get(rowOfTruthTable) == true) ? 1 : 0;
	    	outputValuesToEncrypt[permutedPosition] = allWireValues.get(outputWireIndices[0])[value].getEncoded();
	    }
	    
	    /*
	     * Now encrypt the tweaks on the necessary value. 
	     * Set AES to each value and then look for all rows that need to be encrypted on this value before we reset the key.
	     */
	    for (int i = 0; i < numberOfInputs; i++) {
	    	aes.setKey(allWireValues.get(inputWireIndices[i])[0]);
	    	for (int rowNumber = 0; rowNumber < numberOfRows; rowNumber++) {
	    		if (valuesToEncryptOn[rowNumber][i] == 0) {
	    			byte[] tempo = new byte[aes.getBlockSize()];
	    			aes.computeBlock(tweaksToEncrypt[rowNumber], 0, tempo, 0);
	    			for (int byteNumber = 0; byteNumber < tempo.length; byteNumber++) {
	    				outputValues[rowNumber][byteNumber] ^= tempo[byteNumber];
	    			}
	    		}

	    	}

	    	aes.setKey(allWireValues.get(inputWireIndices[i])[1]);
	    	for (int rowNumber = 0; rowNumber < numberOfRows; rowNumber++) {
	    		if (valuesToEncryptOn[rowNumber][i] == 1) {
	    			byte[] tempo = new byte[aes.getBlockSize()];
	    			aes.computeBlock(tweaksToEncrypt[rowNumber], 0, tempo, 0);
	    			for (int byteNumber = 0; byteNumber < tempo.length; byteNumber++) {
	    				outputValues[rowNumber][byteNumber] ^= tempo[byteNumber];
	    			}
	    		}
	    	}
	    }
	    
	    // Now that we encrypted the tweaks and XOR them to each other, we XOR the result to outputValue, the plaintext.
	    for (int rowNumber = 0; rowNumber < numberOfRows; rowNumber++) {
	    	for (int byteNumber = 0; byteNumber < aes.getBlockSize(); byteNumber++)
	    		outputValues[rowNumber][byteNumber] ^= outputValuesToEncrypt[rowNumber][byteNumber];
	    }
	    
	    // Finally we assign the encrypted results to the corresponding row of the garbled truth table. 
    	for (int rowNumber = 0; rowNumber < numberOfRows; rowNumber++) {
    		System.arraycopy(outputValues[rowNumber], 0, garbledTablesHolder.toDoubleByteArray()[gateNumber], rowNumber * mes.getCipherSize() , mes.getCipherSize());
    	}
	}
}
