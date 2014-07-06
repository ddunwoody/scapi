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

/**
 * This class holds the garbled tables of the extended garbled circuit, it contains the garbled tables of the inner garbled circuit along with 
 * garbled tables of the input identity gates and output identity gates.<p>
 * The garbled circuit will hold an instance of this class and also will the gates. <p>
 * This way, when we want to change the garbled tables, we just have to change the pointer of the tables in this class. 
 * The circuit and the gates will all get the new tables with no time.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ExtendedGarbledTablesHolder implements GarbledTablesHolder{
	
	private static final long serialVersionUID = -8619840329100680441L;
	
	private BasicGarbledTablesHolder inputGarbledTables;	//Garbled tables of input identity gates.
	private BasicGarbledTablesHolder outputGarbledTables;	//Garbled tables of output identity gates.
	private GarbledTablesHolder internalGarbledTables;		//Garbled tables of the internal garbled circuit.
	
	/**
	 * Constructor that gets garbled tables of all gates and sets them.
	 * @param inputGarbledTables - Garbled tables of input identity gates.
	 * @param outputGarbledTables - Garbled tables of output identity gates.
	 * @param internalGarbledTables - Garbled tables of the internal garbled circuit.
	 */
	public ExtendedGarbledTablesHolder(BasicGarbledTablesHolder inputGarbledTables, BasicGarbledTablesHolder outputGarbledTables, GarbledTablesHolder internalGarbledTables){
		this.inputGarbledTables = inputGarbledTables;
		this.outputGarbledTables = outputGarbledTables;
		this.internalGarbledTables = internalGarbledTables;
	}
	
	public BasicGarbledTablesHolder getInputGarbledTables(){
		return inputGarbledTables;
	}
	
	public BasicGarbledTablesHolder getOutputGarbledTables(){
		return outputGarbledTables;
	}
	
	public GarbledTablesHolder getInternalGarbledTables(){
		return internalGarbledTables;
	}

	@Override
	public byte[][] toDoubleByteArray() {
		byte[][] input = inputGarbledTables.toDoubleByteArray();
		byte[][] inner = internalGarbledTables.toDoubleByteArray();
		byte[][] output = outputGarbledTables.toDoubleByteArray();
		
		//Calculate the number of all gates.
		int size = 0;
		if (input != null){
			size += input.length;
		}
		if (inner != null){
			size += inner.length;
		}
		if (output != null){
			size += output.length;
		}
		//Create a big array that hold all gates' garbled tables.
		byte[][] allTables = null;
		if (size > 0){
			allTables = new byte[size][];
		}
		
		int counter = 0;
		//put all garbled tables in the created array.
		if (input != null){
			for (int i=0; i<input.length; i++, counter++){
				allTables[counter] = input[i];
			}
		}
		
		if (inner != null){
			for (int i=0; i<inner.length; i++, counter++){
				allTables[counter] = inner[i];
			}
		}
		
		if (output != null){
			for (int i=0; i<output.length; i++, counter++){
				allTables[counter] = output[i];
			}
		}
		
		return allTables;
	}
	
	public void setGarbledTables(GarbledTablesHolder internalGarbledTables, GarbledTablesHolder inputGarbledTables, GarbledTablesHolder outputGarbledTables){
		if (!(inputGarbledTables instanceof BasicGarbledTablesHolder) || !(outputGarbledTables instanceof BasicGarbledTablesHolder)){
			throw new IllegalArgumentException("The given input and output Garbled Tables should be instances of BasicGarbledTablesHolder");
		}
		this.internalGarbledTables = internalGarbledTables;
		this.inputGarbledTables.setGarbledTables(inputGarbledTables.toDoubleByteArray());
		this.outputGarbledTables.setGarbledTables(outputGarbledTables.toDoubleByteArray());
	}

}
