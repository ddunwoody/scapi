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


package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Vector;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * DlogGroupAbs is an abstract class that implements common functionality of the Dlog group.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class DlogGroupAbs implements primeOrderSubGroup{

	protected GroupParams groupParams;			//group parameters
	protected GroupElement generator;			//generator of the group
	//map for multExponentiationsWithSameBase calculations
	private HashMap<GroupElement, GroupElementsExponentiations> exponentiationsMap = new HashMap<GroupElement, GroupElementsExponentiations>();
	protected SecureRandom random;				//Source of randomness to use.
	//k is the maximum length of a string to be converted to a Group Element of this group. If a string exceeds the k length it cannot be converted.
 	protected int k;
	
	/**
	 * If this group has been initialized then it returns the group's generator. Otherwise throws exception.
	 * @return the generator of this Dlog group
	 */
	public GroupElement getGenerator(){
		
		return generator;
	}
	
	/**
	 * GroupParams are the parameters of the group that define the actual group. That is, different parameters will create a different group. 
	 * @return the GroupDesc of this Dlog group
	 */
	public GroupParams getGroupParams() {
		
		return groupParams;
	}
	
	/**
	 * If this group has been initialized then it returns the group's order. Otherwise throws exception.
	 * @return the order of this Dlog group
	 */
	public BigInteger getOrder(){
		
		return groupParams.getQ();
	}
	
	/**
	 * Checks if the order is a prime number.<p>
	 * Primality checking can be an expensive operation and it should be performed only when absolutely necessary.
	 * @return true if the order is a prime number. false, otherwise.
	 */
	public boolean isPrimeOrder(){
		
		/* isProbablePrime is a BigInteger function, that gets a "certainty" parameter. 
		 * 				   It returns true if this BigInteger is probably prime, false if it's definitely composite
		 * certainty - a measure of the uncertainty that the caller is willing to tolerate: 
		 * 			   if the call returns true the probability that this BigInteger is prime exceeds (1 - 1/2^certainty). 
		 * 			   The execution time of this method is proportional to the value of this parameter. 
		 */
		return (getOrder().isProbablePrime(40));
	}

	/**
	 * Checks if the order is greater than 2^numBits
	 * @param numBits
	 * @return true if the order is greater than 2^numBits, false - otherwise.
	 */
	public boolean isOrderGreaterThan(int numBits){
		if (getOrder().compareTo(new BigInteger("2").pow(numBits)) > 0)
			return true;
		else return false;
	}
	
	/**
	 * Creates a random member of this Dlog group.
	 * 
	 * @return the random element
	 */
	public GroupElement createRandomElement() {
		//This is a default implementation that is valid for all the Dlog Groups and relies on mathematical properties of the generators.
		//However, if a specific Dlog Group has a more efficient implementation then is it advised to override this function in that concrete
		//Dlog group. For example we do so in CryptoPpDlogZpSafePrime.
		BigInteger one = BigInteger.ONE;
		BigInteger qMinusOne = groupParams.getQ().subtract(one);

		// choose a random number x in Zq*
		BigInteger randNum = BigIntegers.createRandomInRange(one, qMinusOne, random);

		// compute g^x to get a new element
		return exponentiate(generator, randNum);

	}

	/**
	 * Creates a random generator of this Dlog group
	 * 
	 * @return the random generator
	 */
	public GroupElement createRandomGenerator() {
		// in prime order groups every element except the identity is a generator.
		// get a random element in the group
		GroupElement randGen = createRandomElement();

		// if the given element is the identity, get a new random element
		while (randGen.isIdentity() == true) {
			randGen = createRandomElement();
		}

		return randGen;

	}

	/*
	 * Computes the simultaneousMultiplyExponentiate using a naive algorithm
	 */
	protected GroupElement computeNaive(GroupElement[] groupElements, BigInteger[] exponentiations){
		int n = groupElements.length; //number of bases and exponents
		GroupElement[] exponentsResult = new GroupElement[n]; //holds the exponentiations result
		
		// raises each element to the corresponding power
		for (int i = 0; i < n; i++) {
			exponentsResult[i] = exponentiate(groupElements[i], exponentiations[i]);
		}
		
		GroupElement result = null; //holds the multiplication of all the exponentiations
		result = getIdentity(); //initialized to the identity element
		
		//multiplies every exponentiate
		for (int i = 0; i<n; i++){
			result = multiplyGroupElements(exponentsResult[i], result);
		}
		
		//return the final result
		return result;
	}
	
	/*
	 * Compute the simultaneousMultiplyExponentiate by LL algorithm.
	 * The code is taken from the pseudo code of LL algorithm in http://dasan.sejong.ac.kr/~chlim/pub/multi_exp.ps.
	 */
	protected GroupElement computeLL(GroupElement[] groupElements, BigInteger[] exponentiations){
		int n = groupElements.length; //number of bases and exponents
		
		//get the biggest exponent
		BigInteger bigExp = BigInteger.ZERO;
		for (int i=0; i<exponentiations.length; i++)
			if (bigExp.compareTo(exponentiations[i])<0)
				bigExp = exponentiations[i];
		
		int t = bigExp.bitLength(); //num bits of the biggest exponent.
		int w = 0; //window size
		
		//choose w according to the value of t
		w = getLLW(t);
		
		//h = n/w
		int h;
		if ((n % w) == 0){
			h = n / w;
		} else{
			h = ((int) (n / w)) + 1;
		}
		
		//create pre computation table
		GroupElement[][] preComp = createLLPreCompTable(groupElements, w, h);
		
		/*for (int i=0; i<h; i++)
			for (int j=0; j<Math.pow(2, w); j++)
				System.out.println(((ECElement) preComp[i][j]).getX());
		*/
		GroupElement result = null; //holds the computation result
		result = getIdentity();
		
		//computes the first loop of the algorithm. This loop returns in the next part of the algorithm with one single tiny change. 
		result = computeLoop(exponentiations, w, h, preComp, result, t-1);
		
		//computes the third part of the algorithm
		for (int j=t-2; j>=0; j--){
			//Y = Y^2
			result = exponentiate(result, new BigInteger("2"));
			
			//computes the inner loop
			result = computeLoop(exponentiations, w, h, preComp, result, j);
		}
		
		return result;
	}
	
	/*
	 * Computes the loop the repeats in the algorithm.
	 * for k=0 to h-1
	 * 		e=0
	 * 		for i=kw to kw+w-1 
	 *			if the bitIndex bit in ci is set:
	 *			calculate e += 2^(i-kw)
	 *		result = result *preComp[k][e]
	 * 
	 */
	private GroupElement computeLoop(BigInteger[] exponentiations, int w, int h, GroupElement[][] preComp, GroupElement result, int bitIndex){
		int e = 0;
		for (int k=0; k<h; k++){
			for (int i=k*w; i<(k * w + w); i++){
				if (i < exponentiations.length){
					//if the bit is set, change the e value
					if (exponentiations[i].testBit(bitIndex) == true){
						int twoPow = (int) (Math.pow(2, i-k*w));
						e += twoPow;
					}
				}
			}
			//multiply result with preComp[k][e]
			result = multiplyGroupElements(result, preComp[k][e]);
			
			e = 0;
		}
		
		return result;
	}
	
	/*
	 * Creates the preComputation table.
	 */
	private GroupElement[][] createLLPreCompTable(GroupElement[] groupElements, int w, int h){
		int twoPowW = (int) (Math.pow(2, w));
		//create the pre-computation table of size h*(2^(w))
		GroupElement[][] preComp = new GroupElement[h][twoPowW];
		
		GroupElement base = null;
		int baseIndex;
		
		//fill the table
		for (int k=0; k<h; k++){
			for (int e=0; e<twoPowW; e++){
				preComp[k][e] = getIdentity();
				
				for (int i=0; i<w; i++){
					baseIndex = k*w + i;
					if (baseIndex < groupElements.length){
						base = groupElements[baseIndex];
						//if bit i in e is set, change preComp[k][e]
						if ((e & (1 << i)) != 0){ //bit i is set
							preComp[k][e] = multiplyGroupElements(preComp[k][e], base);
						}
					}
				}
			}
		}
		
		return preComp;
		
	}
	
	/*
	 * returns the w value according to the given t
	 */
	private int getLLW(int t){
		int w;
		//choose w according to the value of t
		if (t <= 10) {
			w = 2;
		} else if (t <= 24) {
			w = 3;
		} else if (t <= 60) {
			w = 4;
		} else if (t <= 144) {
			w = 5;
		} else if (t <= 342) {
			w = 6;
		} else if (t <= 797) {
			w = 7;
		} else if (t <= 1828) {
			w = 8;
		} else {
			w = 9;
		}
		return w;
	}

	/*
	 * Computes the product of several exponentiations of the same base and
	 * distinct exponents. An optimization is used to compute it more quickly by
	 * keeping in memory the result of h1, h2, h4,h8,... and using it in the
	 * calculation.<p> Note that if we want a one-time exponentiation of h it is
	 * preferable to use the basic exponentiation function since there is no
	 * point to keep anything in memory if we have no intention to use it.
	 * 
	 * @param groupElement
	 * @param exponent
	 * @return the exponentiation result
	 */
	public GroupElement exponentiateWithPreComputedValues(GroupElement groupElement, BigInteger exponent) {
		//extracts from the map the GroupElementsExponentiations object corresponding to the accepted base
		GroupElementsExponentiations exponentiations = exponentiationsMap.get(groupElement);
	
		// if there is no object that matches this base - create it and add it to the map
		if (exponentiations == null) {
			exponentiations = new GroupElementsExponentiations(groupElement);
			exponentiationsMap.put(groupElement, exponentiations);
		}
		// calculates the required exponent
		return exponentiations.getExponentiation(exponent);
		
	}
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.primitives.dlog.DlogGroup#endExponentiateWithPreComputedValues(edu.biu.scapi.primitives.dlog.GroupElement)
	 */
	@Override
	public void endExponentiateWithPreComputedValues(GroupElement base) {
		exponentiationsMap.remove(base);
	}
	
	/**
	 * The class GroupElementExponentiations is a nested class of DlogGroupAbs.<p>
	 * It performs the actual work of pre-computation of the exponentiations for one base.
	 * It is composed of two main elements. The group element for which the optimized computations 
	 * are built for, called the base and a vector of group elements that are the result of 
	 * exponentiations of order 1,2,4,8,… 
	 */
	private class GroupElementsExponentiations {
		private Vector<GroupElement> exponentiations; //vector of group elements that are the result of exponentiations
		private GroupElement base;  //group element for which the optimized computations are built for
		
		/**
		 * The constructor creates a map structure in memory. 
		 * Then calculates the exponentiations of order 1,2,4,8 for the given base and save them in the map.
		 * @param base
		 * @throws IllegalArgumentException
		 */
		public GroupElementsExponentiations(GroupElement base) {
			this.base = base;
			// build new vector of exponentiations
			exponentiations = new Vector<GroupElement>();
			exponentiations.add(0, this.base); // add the base - base^1
			
			BigInteger two = new BigInteger("2");
			for (int i=1; i<4; i++) {
				GroupElement multI;
				multI = exponentiate(exponentiations.get(i-1), two);
					
				exponentiations.add(i, multI);
			}
		}
		
		/**
		 * Calculates the necessary additional exponentiations and fills the exponentiations vector with them.
		 * @param size - the required exponent
		 * @throws IllegalArgumentException
		 */
		private void prepareExponentiations(BigInteger size) {
			//find log of the number - this is the index of the size-exponent in the exponentiation array 
			int index = size.bitLength()-1; 
			
			/* calculates the necessary exponentiations and put them in the exponentiations vector */
			for (int i=exponentiations.size(); i<=index; i++){
				GroupElement multI;
				multI = exponentiate(exponentiations.get(i-1), new BigInteger("2"));
					
				exponentiations.add(i, multI);	
			}
		}
		
		
		/**
		 * Checks if the exponentiations had already been calculated for the required size. 
		 * If so, returns them, else it calls the private function prepareExponentiations with the given size.
		 * @param size - the required exponent
		 * @return groupElement - the exponentiate result
		 */
		public GroupElement getExponentiation(BigInteger size) {
			/**
			 * The exponents in the exponents vector are all power of 2.
			 * In order to achieve the exponent size, we calculate its closest power 2 in the exponents vector 
			 * and continue the calculations from there.
			 */
			// find the the closest power 2 exponent
			int index = size.bitLength()-1;
			
			GroupElement exponent = null;
			/* if the requested index out of the vector bounds, the exponents have not been calculated yet, so calculates them.*/
			if (exponentiations.size() <= index)
				prepareExponentiations(size);
			
			exponent = exponentiations.get(index); //get the closest exponent in the exponentiations vector
			/* if size is not power 2, calculates the additional multiplications */
			BigInteger lastExp = new BigInteger("2").pow(index);
			BigInteger difference = size.subtract(lastExp);
			if (difference.compareTo(BigInteger.ZERO) > 0) {
				GroupElement diff = getExponentiation(size.subtract(lastExp));
				exponent = multiplyGroupElements(diff, exponent);
			}
			
			return exponent;
		}
	}
	
	
	/**
	 * @return the maximum length of a string to be converted to a Group Element of this group. If a string exceeds this length it cannot be converted.
	 */
	public int getMaxLengthOfByteArrayForEncoding() {
		//Return member variable k, which was calculated upon construction of this Dlog group, once the group got the p value. 
		return k;
	}
	
}
