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
import edu.biu.scapi.circuits.encryption.AES128MultiKeyEncryption;
import edu.biu.scapi.exceptions.CannotBeGarbledExcpetion;
import edu.biu.scapi.exceptions.KeyNotSetException;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.PlaintextTooLongException;
import edu.biu.scapi.exceptions.TweakNotSetException;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.primitives.prf.cryptopp.CryptoPpAES;


/**
 * Our code is designed as such that in its constructor
 * {@link StandardGarbledBooleanCircuit} constructs {@code StandardGarbledGate}s.
 * Each {@code StandardGarbledGate} garbled itself by creating a garbled turth
 * table. The garble dtruth table is created row by row. Thus, if we use
 * {@link AES128MultiKeyEncryption} first we will garbled the first row , then
 * the second row etc.. Each row will require two AES operations and two setKey
 * operations--i.e. the key will be set to the garbled value for each row.
 * <p>
 * However, AES set key operations are expensive, and different rows of the
 * truth tables use the same keys. Consider a 2 input gate. There are a total of
 * four keys(a 0 and a 1 for each wire). Yet if we use
 * {@code StandardGarbledBooleanCircuit} with {@code AES128MultiKeyEncryption} we
 * will perform a total of 8 setKey operations. If we garbled the entire truth
 * table together however, we would be able to minimize this to 4 operations.
 * 
 * </p>
 * <p>
 * In order to minimize the number of row operations, we have to couple the
 * garbled gate and the encryption scheme. They can no longer be totally
 * separate entities. This presents an issue however, since for reasons of
 * allowing users to easily extend our code and add new encrypyion schemes, we
 * want the encryption schemes to be totally separate from the
 * {@code GarbledGate}s. (See <i>Garbling * Schemes </i> by Mihir Bellare, Viet
 * Tung Hoang, and Phillip Rogaway for their discussion on garbling schemes as
 * an entity in their own right). Therefore, we create the specialized {code
 * {@link MinimizeAESSetKeyGarbledBooleanCircuit} and
 * {@code MinimizeAESSetKeyGarbledGate} to allow us to minimize the number of
 * setKey operations while still in general decoupling garbling encryption
 * schemes from the gates and circuits.
 * </p>
 * <p> The only difference of this class from {@code StandardGarbledBooleanCircuit} is that it uses {@code {@link MinimizeAESSetKeyGarbledGate}}s instead of {@code StandardGarbledGate}s. All of the major differences that we discussed take place in {@link MinimizeAESSetKeyGarbledGate}.
 * <p> Note that currently only the constructor and not the verify method minimizes AES set key calls
 * @author Steven Goldfeder
 * 
 */
public class MinimizeAESSetKeyGarbledBooleanSubCircuit extends AbstractGarbledBooleanSubCircuit implements Serializable {


	private static final long serialVersionUID = 5446891779903584134L;


/**
   * Constructs a garbled circuit using {@link AES128MultiKeyEncryption} while
   * minimizing the number od setKey operations performed.
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
   * @param inputTranslationTable 
   * 		  the translation table of the input. It is important when the input keys are given
   * 		  as a parameter. The relates signal bits must be supplied too in this case.
   *          
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
   * @throws PlaintextTooLongException
   * @throws TweakNotSetException
   * @throws KeyNotSetException
   * @throws IllegalBlockSizeException
   * @throws InvalidKeyException
   * @throws NoSuchPartyException 
 * @throws CannotBeGarbledExcpetion 
   */
  public MinimizeAESSetKeyGarbledBooleanSubCircuit(BooleanCircuit ungarbledCircuit,
			Map<Integer, SecretKey[]> allInputWireValues, Map<Integer, Integer> inputTranslationTable,
			Map<Integer, SecretKey[]> allOutputWireValues, Map<Integer, Integer> translationTable) throws InvalidKeyException,
      IllegalBlockSizeException, KeyNotSetException, TweakNotSetException,
      PlaintextTooLongException, NoSuchPartyException, CannotBeGarbledExcpetion {
	  
	  Map<Integer, SecretKey[]> allWireValues = new HashMap<Integer, SecretKey[]>();
	  Map<Integer, Integer> signalBits = new HashMap<Integer, Integer>();
	     
	  
 
    subCircuitCreator(ungarbledCircuit, allInputWireValues,
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
  protected MinimizeAESSetKeyGarbledBooleanSubCircuit(){
	  
  }

  	/**
	 * 
	 * Does the actual construction. This is called both from this class constructor and the child class constructor.
	 * 
	 */
	protected void subCircuitCreator(BooleanCircuit ungarbledCircuit,
			Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, Integer> inputTranslationTable,
			Map<Integer, SecretKey[]> allWireValues,
			Map<Integer, Integer> signalBits) throws NoSuchPartyException,
			CannotBeGarbledExcpetion, InvalidKeyException,
			IllegalBlockSizeException, KeyNotSetException, TweakNotSetException,
			PlaintextTooLongException {
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
	    
	    Gate[] ungarbledGates = ungarbledCircuit.getGates();
	    numberOfWires = ungarbledCircuit.getNumberOfWires();
	    gates = new GarbledGate[ungarbledGates.length];
	    garbledTables = new byte[ungarbledGates.length][];
	    
	    SecureRandom random = new SecureRandom();
	    
	    //this will be passed to the gates for encryption
	    PseudorandomFunction aes = new CryptoPpAES();
	
	    /*this will be passed to the gates and used for decryption and (for now) verifying. Eventually, verifying willl
	    *also minimize setKey operations and use aes directly
	    */
	    mes = new AES128MultiKeyEncryption();
	
	    if(allInputWireValues.isEmpty()){//we need to create the secret keys and signal bits
			
			for (int w : partyOneInputWireLabels) {
				fillIWireKeysAndSignalBit(allInputWireValues, inputTranslationTable, random, w);
			}
			for (int w : partyTwoInputWireLabels) {
				fillIWireKeysAndSignalBit(allInputWireValues, inputTranslationTable, random, w);
	      }
		}
	    //set the keys of the input wires and the signal bits. Either filled here in the constructor or given as an argument
		allWireValues.putAll(allInputWireValues);
		signalBits.putAll(inputTranslationTable);
		
	
		
		/*  now that all wires have garbled values, we create the individual garbled
	     gates*/
	    for (int gate = 0; gate < gates.length; gate++) {
	    	
			//for each gate fill the keys and signal bits for output wires since they are not filled yet.
			for (int i = 0; i < ungarbledGates[gate].getOutputWireLabels().length; i++) {
				
				fillIWireKeysAndSignalBit(allWireValues, signalBits, random, ungarbledGates[gate].getOutputWireLabels()[i]);
			}
	
	      //here we use MinimizeAESSetKeyGarbledGate and not StandardGarbledGate
	      gates[gate] = new MinimizeAESSetKeyGarbledGate(this, ungarbledGates[gate],
	          allWireValues, signalBits,aes);
	    }
	}


	/**
	 * Builds both keys of wire {@code w} and a random signal bit. 
	 */
	private void fillIWireKeysAndSignalBit(	Map<Integer, SecretKey[]> allWireValues,
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
	      allWireValues.put(wireLabel, new SecretKey[] { zeroValue, oneValue });
	}
}
