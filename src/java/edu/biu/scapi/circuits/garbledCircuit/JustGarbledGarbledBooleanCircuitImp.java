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

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.circuits.circuit.Wire;
import edu.biu.scapi.exceptions.NoSuchPartyException;
import edu.biu.scapi.exceptions.NotAllInputsSetException;

/**
 * A concrete implementation of GarbledBooleanCircuit that is an implementation of the justGarbled library.<p>
 * The circuit can be used as a regular circuit in java and the actual calculations are done in the c++ jni dll
 * calling functions in the JustGarbled library. In some cases, there is a need to get back information that 
 * is stored in the java class (such as the garbled tables, input keys, etc). In that case we translate the information
 * from the jni and convert it to the way the SCAPI garbled circuit saves the information. This may consume time
 * since java and the dll do not share memory. However, this gives us the flexibility to work from java, for example 
 * with 2 parties and sending information via the java channel. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class JustGarbledGarbledBooleanCircuitImp extends GarbledBooleanCircuitAbs {
	
	private static final int JUST_GARBLED_KEY_SIZE = 16;//The number of bytes in each just garbled key 

	protected long garbledCircuitPtr = 0; //Pointer to the native garbledCircuit object
	private int[] inputsIndices;//The indexes for the input returned from the jni. There is no assumption that the input indices are from 0 to numOfInputs-1.
								//Changes have been made to the JustGarbled  library to support this change.
	
	//utility native functions written in the jni dll
	private native void converScapiCircuitFileToJustGarbledCircuitFile(String fileName);//Converts SCAPI file to JustGarbled file. The returned file has the same name
																						//with the .scd extension. Note that more information has been added to the file
																						//and thus passing a regular .scd that was not created by SCAPI will not work
	
	
	private native long createGarbledcircuit(String fileNameJustGarbled);//Creates a garbled circuit from .scd file. It returns the pointer to that circuit saved in the dll memory 
	private native int[] getOutputIndicesArray(long ptr);//Returns the output indices taken from the scd file.
	private native int[] getInputIndicesArray(long ptr);//Returns the input indices taken from the scd file..
	private native int[] getInputIndicesForEachParty(long ptr);//Returns an array that stores the number of inputs for each party
	private native void setGarbleTables(long ptr, byte[] garbledTable);//Sets the garbled tables. This is a costly function since we need to pass a large amount of information
																	   //from the java memory to the c++ jni memory space
																			
	private native byte[] getGarbleTables(long ptr);//Gets the garbled tables from the jni dll. Again, this is a costly functions since we neet to pass a large amount of information
													//from the dll memory space to the java memory space.
	private native long garble(long ptr, byte[] inputKeys, byte[] outputKeys);//Does the garbling of the circuit, returns the input keys and the output keys that were generated
																			  //by the circuit. The input and the output keys are converted to the structures that are defined 
																			  //in the SCAPI circuit
	private native byte[] eval(long ptr, byte[] inputKeys);//Does the compute and returns the output keys that are the results.
	private native void deleteCircuit(long ptr);//Deletes the memory of the circuit in the dll.
	
	
	
	/**
	 * A constructor that gets an input a file name. The two options are either .txt file which is the SCAPI template of a circuit or .scd which 
	 * is a file that we create in SCAPI for just garble to extract.<p>
	 * For the .scd case, the created circuit is "empty", it holds the structure of the circuit but the garbled tables. <p>
	 * In the case where a .txt is passed no circuit is actually created, rather, it just creates a .scd to use later on.
	 * @param fileNameJustGarbled the name of the circuit file ending with either .txt (SCAPI circuit format) extension or .scd (JustGarbled format) extension.
	 */
	public JustGarbledGarbledBooleanCircuitImp(String fileNameJustGarbled){
		
		String fileExtension = fileNameJustGarbled.substring( fileNameJustGarbled.length() - 3, fileNameJustGarbled.length());
		
		if(fileExtension.equals("txt")){
		
			//Convert the file into an .scd file with the same name. An actual circuit is not created
			converScapiCircuitFileToJustGarbledCircuitFile(fileNameJustGarbled);
			return;
		}
		else if(fileExtension.equals("scd")){
			//Creates a new circuit body based on the structure defined by the file
			garbledCircuitPtr = createGarbledcircuit(fileNameJustGarbled);
		}
		
		//Init the parties array lists that are held in the base abstract class
		eachPartysInputWires = new ArrayList<ArrayList<Integer>>();
		
		//Get the indices defined in the file from the dll.
		inputsIndices = getInputIndicesArray(garbledCircuitPtr);
		//Get the number of inputs for each party
		int[] InputIndicesForEachParty = getInputIndicesForEachParty(garbledCircuitPtr);
    	
    	//Read the input wires labels and place them in the eachPartysInputWires double array list
		int accum = 0;
    	for (int i = 0; i < InputIndicesForEachParty.length; i++) {
    		ArrayList<Integer> partyInput = new ArrayList<Integer>();
    		for(int j=0; j<InputIndicesForEachParty[i];j++){
    			
    			partyInput.add(inputsIndices[accum]);
    			accum++;
    		}
    		eachPartysInputWires.add(partyInput);
    	}
    	
    	//Get the number of parties read from the file stored in the dll circuit 
    	numberOfParties = InputIndicesForEachParty.length;
    	//get the output array indices from the jni
    	outputWireIndices = getOutputIndicesArray(garbledCircuitPtr);
    	
    	
    	
	}


	
	/**
	 * Does the garbaling of the circuit in the dll. It stores these tables in the dll circuit and can be accessed by the pointer to this
	 * circuit. It also generates the input and output keys and stores them in the java class. In addition, since JustGarbled does not have
	 * a translation table, it creates one and stores it in the java attribute translationTable of the abstract base class.
	 */
  	public CircuitCreationValues garble() {
		System.out.println("time at begining of garble " + System.currentTimeMillis());
		//Init the translation table
		translationTable = new HashMap<Integer, Byte>();
		Map<Integer, SecretKey[]> allInputWireValues = new HashMap<Integer, SecretKey[]>();
		Map<Integer, SecretKey[]> allOutputWireValues = new HashMap<Integer, SecretKey[]>();
		
		int numOfInputs = inputsIndices.length;
		
		//create empty input and output arrays to get the keys that JustGarbled had created
		byte[] inputKeys = new byte[numOfInputs*JUST_GARBLED_KEY_SIZE*2];
		byte[] outputKeys  = new byte[outputWireIndices.length*JUST_GARBLED_KEY_SIZE*2];
		
		System.out.println("before garble " + System.currentTimeMillis());
		//long startTime = System.currentTimeMillis();
		
		//call the native function of garble
		garble(garbledCircuitPtr, inputKeys, outputKeys);
		//long estimatedTime = System.currentTimeMillis() - startTime;
		//System.out.println("call to garble took "+estimatedTime+" milis");
		System.out.println("after garble " + System.currentTimeMillis());
		
		Date start2 = new Date();
		//Convert the input keys of the jni to the circuit input keys
		convertInputAndOutputKeysOfJustGarbledToScapi(allInputWireValues,
				allOutputWireValues, numOfInputs, inputKeys, outputKeys);
		Date end2 = new Date();
		long time2 = end2.getTime() - start2.getTime();
		System.out.println("convert input and output to java took "+time2+" milis");
		
		System.out.println(System.currentTimeMillis());
		
		
		Date start3 = new Date();
		
		//Create the translation table according to the output keys
		createTranslationTable(allOutputWireValues);
		Date end3 = new Date();
		long time3 = end3.getTime() - start3.getTime();
		System.out.println("create translation table took "+time3+" milis");
		
		//Generate a CircuitCreationValues object that must be returned according to the 
		CircuitCreationValues outputVal = new CircuitCreationValues(allInputWireValues, allOutputWireValues, translationTable);
		
		System.out.println("time at the end of garble " + System.currentTimeMillis());
		return outputVal;
	}
	
	
	/**
	 * Creates the translation table of the just garbled circuit. Since we have both keys and we know which one is the zero-key, we copy the 
	 * signal bit of the zero key
	 * @param allOutputWireValues
	 */
	private void createTranslationTable(
			Map<Integer, SecretKey[]> allOutputWireValues) {
		
		//Fill the the output wire values to be used in the following sub circuit
		for (int n : outputWireIndices) {
			
			//Signal bit is the signal bit of the first byte of the first key
			byte[] k0 = allOutputWireValues.get(n)[0].getEncoded();
			translationTable.put(n, (byte) ((k0[0] % 2 + 2)%2));			}
	}
		
	/**
	 * Converts the input and the output stored in the just garbled circuit to the structures defined in the SCAPI circuit.
	 *
	 */
	private void convertInputAndOutputKeysOfJustGarbledToScapi(
			Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, SecretKey[]> allOutputWireValues, int numOfInputs,
			byte[] inputKeys, byte[] outputKeys) {
		
		//Copy the input keys 
		for(int i=0; i<numOfInputs; i++){
		
			
			//copy the zero and one keys
			byte[] key0 = Arrays.copyOfRange(inputKeys, i*2*JUST_GARBLED_KEY_SIZE, i*2*JUST_GARBLED_KEY_SIZE + JUST_GARBLED_KEY_SIZE);
			byte[] key1 = Arrays.copyOfRange(inputKeys, i*2*JUST_GARBLED_KEY_SIZE+JUST_GARBLED_KEY_SIZE, i*2*JUST_GARBLED_KEY_SIZE + 2*JUST_GARBLED_KEY_SIZE);
			
			//create the pair of keys
			SecretKey[] secretKeys = new SecretKey[]{new SecretKeySpec(key0, ""), new SecretKeySpec(key1, "")};
			
			//add the keys to the map
			allInputWireValues.put(inputsIndices[i], secretKeys);
			
		}
		
		
		//Copy the output keys
		for(int i=0; i<outputWireIndices.length; i++){
			
			//get the 2 keys for each wire. Since aes is used there are JUST_GARBLED_KEY_SIZE bytes for each wire key
			byte[] key1 = Arrays.copyOfRange(outputKeys, i*2*JUST_GARBLED_KEY_SIZE, i*2*JUST_GARBLED_KEY_SIZE + JUST_GARBLED_KEY_SIZE);
			byte[] key2 = Arrays.copyOfRange(outputKeys, i*2*JUST_GARBLED_KEY_SIZE+JUST_GARBLED_KEY_SIZE, i*2*JUST_GARBLED_KEY_SIZE + 2*JUST_GARBLED_KEY_SIZE);
			
			//create the pair of keys
			SecretKey[] secretKeys = new SecretKey[]{new SecretKeySpec(key1, ""), new SecretKeySpec(key2, "")};
			
			//add the keys to the map
			allOutputWireValues.put(outputWireIndices[i], secretKeys);
			
		}
	}
	
 
  	/**
  	 * Does the computation of the circuit. It returns the keys and not 0/1 answer. In order to receive a 0/1 answer
  	 * a call to translate is needed.
  	 */
  	public HashMap<Integer, GarbledWire> compute() throws NotAllInputsSetException{
  		
  		HashMap<Integer, GarbledWire> garbledOutput = new HashMap<Integer, GarbledWire>();
  		
  		int numOfInputs = inputsIndices.length;
		
		//First check that all the inputs are set
		for (int wireNumber : inputsIndices){
  			if (!computedWires.containsKey(wireNumber)) {
  				throw new NotAllInputsSetException();
  			}
  		}
		
  		
  		byte [] inputKeys = new byte[numOfInputs*JUST_GARBLED_KEY_SIZE];//the input keys that are related to the input of all parties
  		byte [] outputKeys = new byte[outputWireIndices.length*JUST_GARBLED_KEY_SIZE];
  		byte [] key = null;
  		
  		//Get the input keys from the computedwires which after setInput should hold all the input keys in a GarbledWire class
  		for (int i = 0; i<numOfInputs; i++ ) {
  			
  			//Get the key related to the input that was set from the garbled wire
  			key = computedWires.get(inputsIndices[i]).getValueAndSignalBit().getEncoded();
  			
  			//Copy the key of the input into the inputKeys array that will eventually be sent to the jni dll
  			System.arraycopy(key, 0,inputKeys , i*JUST_GARBLED_KEY_SIZE, JUST_GARBLED_KEY_SIZE);
  			
  		}
  		
  		//call the native function eval that does the computing.
  		outputKeys = eval(garbledCircuitPtr, inputKeys);
  		
  		
  		//Copy the answer of the native function eval to the hash of garbled wires
  		int i=0;
  		for (int w : outputWireIndices) {
  			
  			key = Arrays.copyOfRange(outputKeys, i*JUST_GARBLED_KEY_SIZE, (i+1)*JUST_GARBLED_KEY_SIZE);
  			
  			garbledOutput.put(w, new GarbledWire(new SecretKeySpec(key, "")));
  			
  			i++;
  		}
  		
  		//return the garbled values
  		return garbledOutput;
  	}	

	
  	/**
	 * Translates from the resulting garbled wires to wires with 0/1 values.
	 * @param garbledOutput The result of computing the circuit. 
	 * This result is given in garbled wires and will be translated according to the translation table.
	 * @return the translated results as wires of the boolean circuit where the values of the wires are set.
	 */
  	public Map<Integer, Wire> translate(Map<Integer, GarbledWire> garbledOutput){
  		
		Map<Integer, Wire> translatedOutput = new HashMap<Integer, Wire>();
	    byte signalBit, bitOnWire;
	    byte[] key;
		
	    //Go through the output wires.
	    for (int w : outputWireIndices) {
	    	signalBit = translationTable.get(w);
	    	key = garbledOutput.get(w).getValueAndSignalBit().getEncoded();
	    	
	    	//In just garbled the signal bit is list significant bit of the first byte. Thus mod 2 is sufficient.
	    	//Since java may return a negative value we add 2 to the result of mod and mod again. 
	    	bitOnWire = (byte) ((key[0] %2 + 2)%2);
	      
	    	//Calculate the resulting value.
	    	byte value = (byte) (signalBit ^ bitOnWire);
	    	System.out.print(value);
	    	
	    	//Hold the result as a wire.
	    	Wire translated = new Wire(value);
	    	translatedOutput.put(w, translated);
	    }
	    System.out.println();
	    return translatedOutput;

	}
	
  	/**
  	 * Returnes the input wire indices
  	 */
	public List<Integer> getInputWireIndices(int partyNumber) throws NoSuchPartyException {
		if (partyNumber>numberOfParties){
  			throw new NoSuchPartyException();
  		}
		return eachPartysInputWires.get(partyNumber-1);
	}

  
	/**
	 * Returns the garbledTablesHolder if it was already created. Otherwise it gets it from the jni thru the native function getGarbleTables.
	 */
	public GarbledTablesHolder getGarbledTables(){
		
		
		if(garbledTablesHolder==null){//the garbled table was never returned from the dll
			
			//get the garbled tables from the circuit held in the dll
			byte[] garbledTables = getGarbleTables(garbledCircuitPtr);
			
			garbledTablesHolder = new JustGarbledGarbledTablesHolder(garbledTables);
			
		}
		
		
		return garbledTablesHolder;
	}
  
	/**
	 * Sets new garbled tables to the circuit. This actualy copies the large memory held in java to the c++ jni and thus, may be 
	 * a costly function. 
	 */
	public void setGarbledTables(GarbledTablesHolder garbledTables){
		
		if (!(garbledTables instanceof JustGarbledGarbledTablesHolder)){
			throw new IllegalArgumentException("garbledTables should be an instance of JustGarbledGarbledTablesHolder");
		}
		
		//set the new garbled tables in the dll as well. The garbled tables are held in the first location of the double byte array.
		setGarbleTables(garbledCircuitPtr, garbledTables.toDoubleByteArray()[0]);
		
		garbledTablesHolder = garbledTables;
	}
	
	

	@Override
	public CircuitCreationValues garble(byte[] seed) throws InvalidKeyException {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	public boolean internalVerify(Map<Integer, SecretKey[]> allInputWireValues,
			Map<Integer, SecretKey[]> allOutputWireValues) {
		// TODO Auto-generated method stub
		return false;
	}
	
	
	/**
	 * returns the signal bit related to the given key.
	 */
	byte getKeySignalBit(SecretKey key) {
		
		
    	//in just garbled the signal bit is the list significant bit of the first byte. Thus mod 2 is sufficient.
    	//Since java may return a negative value we add 2 to the result of mod and mod again. 
    	return (byte) ((key.getEncoded()[0] %2 + 2)%2);
	}

	
	
	static {
		 
		 //loads the JustGarbledJavaInterface jni dll
		 System.loadLibrary("JustGarbledJavaInterface");
	}


	
}
