/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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


import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.BooleanCircuit;
import edu.biu.scapi.circuits.circuit.InvalidInputException;
import edu.biu.scapi.circuits.circuit.NoSuchPartyException;
import edu.biu.scapi.circuits.encryption.AESFixedKeyMultiKeyEncryption;
import edu.biu.scapi.circuits.encryption.HashingMultiKeyEncryption;
import edu.biu.scapi.circuits.encryption.InvalidKeySizeException;
import edu.biu.scapi.circuits.encryption.KeyNotSetException;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.circuits.encryption.PlaintextTooLongException;
import edu.biu.scapi.circuits.encryption.TweakNotSetException;
import edu.biu.scapi.circuits.garbledCircuit.CannotBeGarbledExcpetion;
import edu.biu.scapi.circuits.garbledCircuit.FreeXORGarbledBooleanCircuit;
import edu.biu.scapi.circuits.garbledCircuit.FreeXORGarbledBooleanCircuitSlim;
import edu.biu.scapi.circuits.garbledCircuit.GarbledBooleanCircuit;
import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;


public class YaoP1 implements Protocol, MessageReceiver{

	private Channel channel = null;
	private DlogGroup dlog = null;
	private GarbledBooleanCircuit gbc = null;
	private Map<Integer, SecretKey[]> allInputWireValues = null;
	private BatchOtDdhSemiHonestSender bOTSender= null;
	private KeyDerivationFunction kdf;
	
	private BooleanCircuit[] subCircuits;
	private int numOfInputs = 0;
		
	
	/**
	 * Creates the Yao's Protocol for Party 1. 
	 * 
	 * @param channel - the channel for communicating between the two parties
	 * @param dlog - the dlog group to be used in the proctocol. Must be the same in both parties.
	 * @param kdf - the key derivation function to be used in the protocol. Must be the same in both parties.
	 * @param bc - the ungarbled original boolean circuit.  Must be the same in both parties.
	 * @throws CannotBeGarbledExcpetion
	 */
	YaoP1(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf, BooleanCircuit bc) throws CannotBeGarbledExcpetion{ 
		
		this.channel = channel;	
		this.dlog = dlog;
		this.kdf = kdf;
		try {
			
			Date start = new Date();
			
			
			//MultiKeyEncryptionScheme mes = new HashingMultiKeyEncryption(80);
			MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
		    allInputWireValues = new HashMap<Integer, SecretKey[]>();
		   
		    gbc = new FreeXORGarbledBooleanCircuitSlim(bc, mes, allInputWireValues);
		   
		    
			Date end = new Date();
			long time = (end.getTime() - start.getTime());
			System.out.println("Yao's protocol create garbled circuit took " +time + " milis");
			
			
		
		    start = new Date();
		    //get the my input and set it in the garbled circuit
		    gbc.setGarbledInputFromUngarbledFile(new File("AESPartyOneInputs.txt"), allInputWireValues,1);
		    end = new Date();
			time = (end.getTime() - start.getTime());
			System.out.println("Yao's protocol set input from file to garbled circuit took " +time + " milis");
			
		    
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FactoriesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyNotSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TweakNotSetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PlaintextTooLongException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPartyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	}
	
	
	/**
	 * Creates the Yao's Protocol for Party 1. 
	 * 
	 * @param channel - the channel tfor communicating between the two parties
	 * @param dlog - the dlog group to be used in the proctocol. Must be the same in both parties.
	 * @param kdf - the key derivation function to be used in the protocol. Must be the same in both parties.
	 * @param bc - the ungarbled original boolean circuit.  Must be the same in both parties.
	 * @throws CannotBeGarbledExcpetion
	 */
	YaoP1(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf, BooleanCircuit[] subCircuits) throws CannotBeGarbledExcpetion{ 
		
		this.channel = channel;	
		this.dlog = dlog;
		this.kdf = kdf;
		this.subCircuits = subCircuits.clone();
		
	    
	   
	}


	@Override
	/**
	 * run the yao's protocol for party 1. 
	 * 
	 * 1. sends the garbled circuit
	 * 2. runs the oblivious transfer sub protocol in order for party 2 to get its 
	 * 
	 */
	public void run() {

		//send the circuit and the input to P2
		try {
			
			Date start = new Date();
			//send garbled circuit and my input keys to P2
			channel.send((Serializable) gbc);
			
			
			Date end = new Date();
			long time = (end.getTime() - start.getTime());
			System.out.println("Yao's protocol send circuit 1 took " +time + " milis");
			
			
			//get the number of inputs of P2. These are the inputs we do the OY on
			int numOfP2Inputs = gbc.getNumberOfInputs(2);
			
			
			start = new Date();
			//create the OT as the sender
			bOTSender = new BatchOtDdhSemiHonestSender(channel, numOfP2Inputs, allInputWireValues, gbc.getInputWireLabels(2), dlog, kdf);
			
			
			//run the OT
			bOTSender.run();
			
			end = new Date();
			time = (end.getTime() - start.getTime());
			System.out.println("OT took " +time + " milis");
			
			//get the output from P2
			//Map<Integer, Wire> Output =  (Map<Integer, Wire>) channel.receive();
			
			
		
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPartyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
//		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	/**
	 * run the yao's protocol for party 1 where the circuit is sent in pieces.
	 * 
	 *  in order for Party 2 to start computing the circuit we need now to change the order and first do the oblivious transfer
	 *  so party 2 will have its input keys.
	 * 
	 * 1. runs the oblivious transfer sub protocol in order for party 2 to get its
	 * 2. send the garbled circuit in pieces 
	 * @throws CannotBeGarbledExcpetion 
	 * 
	 */
	public void runWithSubCircuits() throws CannotBeGarbledExcpetion {

		try {
			
			
			//variables to use for the garbled circuits
			MultiKeyEncryptionScheme mes = new HashingMultiKeyEncryption(80);
			
			Map<Integer, SecretKey[]> allOutputWireValues = new HashMap<Integer, SecretKey[]>();
			Map<Integer, Integer> outputTranslationTable = new HashMap<Integer, Integer>();
			
		    allInputWireValues = new HashMap<Integer, SecretKey[]>();
		    int numOfP2Inputs = 0;
		    
			try {
				
				Date start = new Date();
				
				//create the garbled circuit from the boolean circuit and get the allInputWireValues with both keys for the inputs
			    gbc = new FreeXORGarbledBooleanCircuit(subCircuits[0], mes, allInputWireValues, allOutputWireValues, outputTranslationTable);
			   
			    
				
				
				//get the my input and set it in the garbled circuit
			    gbc.setGarbledInputFromUngarbledFile(new File("AESPartyOneInputs.txt"), allInputWireValues,1);
			    
				Date end = new Date();
				long time = (end.getTime() - start.getTime());
				System.out.println("Yao's set party 1 input took " +time + " milis");
				
				
				//get the number of inputs of P2. These are the inputs we do the OT on
				numOfP2Inputs = gbc.getNumberOfInputs(2);
				
				start = new Date();
				
				//create the OT as the sender
				bOTSender = new BatchOtDdhSemiHonestSender(channel, numOfP2Inputs, allInputWireValues, gbc.getInputWireLabels(2), dlog, kdf);
				
				
				//run the OT
				bOTSender.run();
				 end = new Date();
				time = (end.getTime() - start.getTime());
				System.out.println("OT took " +time + " milis");
				
				
				
				start = new Date();
				//send garbled circuit and my input keys to P2
				channel.send((Serializable) gbc);
				
				
				end = new Date();
				time = (end.getTime() - start.getTime());
				System.out.println("Yao's protocol send circuit 1 took " +time + " milis");
				
				//now construct the rest of the sub circuits and send each piece
				
				int numberOfSubCircuits = subCircuits.length;
				Map<Integer, SecretKey[]> allOutputPreviousWireValues = new HashMap<Integer, SecretKey[]>();
				Map<Integer, SecretKey[]> allOutputCurrentWireValues = new HashMap<Integer, SecretKey[]>();
				
				allOutputPreviousWireValues.putAll(allOutputWireValues);
				for(int i=1; i<numberOfSubCircuits; i++){
					
					allOutputCurrentWireValues.clear();
					gbc = new FreeXORGarbledBooleanCircuit(subCircuits[i], mes, allOutputPreviousWireValues, allOutputCurrentWireValues, outputTranslationTable);
					
					//append the output wires. We append the result instead of replacing since sub circuit 4 might need input from sub circuits 2 and 3.
					allOutputPreviousWireValues.putAll(allOutputCurrentWireValues);
					
					start = new Date();
					
					//send the garbled sub circuit
					channel.send((Serializable) gbc);
					
					
					end = new Date();
					time = (end.getTime() - start.getTime());
					System.out.println("Yao's protocol send circuit 1 took " +time + " milis");
					
				}
			
			    
			    
				
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyNotSetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (TweakNotSetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (PlaintextTooLongException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPartyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidInputException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
		
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FactoriesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	
	/**
	 * run the yao's protocol for party 1. 
	 * 
	 * 1. sends the garbled circuit
	 * 2. runs the oblivious transfer sub protocol in order for party 2 to get its 
	 * 
	 */
	public void runWithThreads() {

		//send the circuit and the input to P2
		try {
			
			Date start = new Date();
			//send garbled circuit and my input keys to P2
			channel.send((Serializable) gbc);
			
			
			Date end = new Date();
			long time = (end.getTime() - start.getTime());
			System.out.println("Yao's protocol send circuit 1 took " +time + " milis");
			
			
			//get the number of inputs of P2. These are the inputs we do the OY on
			int numOfP2Inputs = gbc.getNumberOfInputs(2);
			
			
			start = new Date();
			//create the OT as the sender
			bOTSender = new BatchOtDdhSemiHonestSender(channel, numOfP2Inputs, allInputWireValues, gbc.getInputWireLabels(2), dlog, kdf);
			
			
			//run the OT
			bOTSender.run();
			
			end = new Date();
			time = (end.getTime() - start.getTime());
			System.out.println("OT took " +time + " milis");
			
			//get the output from P2
			//Map<Integer, Wire> Output =  (Map<Integer, Wire>) channel.receive();
			
			
		
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPartyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
//		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	

	@Override
	public void processMessage(Object msg) {
		// TODO Auto-generated method stub
		
	}
	
	
	public createGarbledInputKeys(Map<Integer, SecretKey[]> allInputWireValues ){
		
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
		//
		for (int w : partyOneInputWireLabels) {
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
			allInputWireValues.put(w, new SecretKey[] { zeroValue, oneValue });
		}
		for (int w : partyTwoInputWireLabels) {
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


	@Override
	public ProtocolOutput getOutput() {
		// TODO Auto-generated method stub
		return null;
	}



	
}
