package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;
import java.util.HashMap;
//import java.util.LinkedList;
//import java.util.ListIterator;
import java.util.Vector;

import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * DlogGroupAbs is an abstract class that implements common functionality of the Dlog group.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class DlogGroupAbs implements DlogGroup{

	protected GroupParams groupParams;			//group parameters
	protected GroupElement generator;			//generator of the group
	//map for multExponentiationsWithSameBase calculations
	private HashMap<GroupElement, GroupElementsExponentiations> exponentiationsMap = new HashMap<GroupElement, GroupElementsExponentiations>();
	
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
	 * Checks if the order is a prime number
	 * @return true if the order is a prime number. false, otherwise.
	 */
	public boolean isPrimeOrder(){
		
		/* isProbablePrime is BigInteger function, which gets a certainty parameter.
		 * We will test some values to decide which is appropriate to our demands.
		 */
		if (getOrder().isProbablePrime(40))
			return true;
		else return false;
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
	
	/*
	 * Computes the simultanouesMultiplyExponentiate by the native algorithm
	 */
	protected GroupElement computeNaive(GroupElement[] groupElements, BigInteger[] exponentiations){
		int n = groupElements.length; //number of bases and exponents
		GroupElement[] exponentsRasult = new GroupElement[n]; //holds the exponentiations result
		
		//raises each element to the corresponding power
		for (int i = 0; i<n; i++){
			exponentsRasult[i] = exponentiate(groupElements[i], exponentiations[i]);
		}
		
		GroupElement result = null; //holds the multiplication of all the exponentations
		result = getIdentity(); //initialized to the identity element
		
		//multiplies every exponentiate
		for (int i = 0; i<n; i++){
			result = multiplyGroupElements(exponentsRasult[i], result);
		}
		
		//return the final result
		return result;
	}
	
	/*
	 * Compute the simultanouesMultiplyExponentiate by LL algorithm.
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
		if (t <= 10){
			w = 2;
		} else if (t <= 24){
			w = 3;
		} else if (t <= 60){
			w = 4;
		} else if (t <= 144){
			w = 5;
		} else if (t <= 342){
			w = 6;
		} else if (t <= 797){
			w = 7;
		} else if (t <= 1828){
			w = 8;
		} else {
			w = 9;
		}
		return w;
	}
	
	/*
	 * Compute the simultanouesMultiplyExponentiate by WU algorithm.
	 * The code is taken from the pseudo code of WU algorithm in http://dasan.sejong.ac.kr/~chlim/pub/multi_exp.ps.
	 */
	/*private GroupElement computeWU(GroupElement[] groupElements, BigInteger[] exponentiations){
		int n = groupElements.length; //number of bases and exponents
		
		//get the biggest exponent
		BigInteger bigExp = BigInteger.ZERO;
		for (int i=0; i<exponentiations.length; i++)
			if (bigExp.compareTo(exponentiations[i])<0)
				bigExp = exponentiations[i];
		
		int t = bigExp.bitLength(); //num bits of the biggest exponent.
		int w = 0; //window size
		
		//choose w according to the value of t
		w = getWUW(t);
		
		//create the pre-computation table of size n*(2^(w-1)+1)
		GroupElement[][] preComp = createWUPreCompTable(groupElements, w, n);
		
		LinkedList<lValue> list = new LinkedList<lValue>(); //contains the li,j values
		HashMap<String,Integer> map = new HashMap<String,Integer>(n*t); //contains the ci,j values
		
		
		//calculates the li,j and ci,j and fill these values in li,j list and ci,j map
		int len = fillListAndMap(exponentiations, list, map, n, w);
		
		GroupElement result = null; //holds the computation result
		result = getIdentity();
		
		//the list is sorted such that the maximum value is the first element in the list.
		//by each list.pop we get the current max value in the list
		lValue l= list.pop(); 
		//compute y<-Yi,(ci,ki+1)/2 for each i such that li,ki = len
		while(l.getVal() == len){
			//calculate result *=Yi,(ci,ki+1)/2, for i such that li,ki = len
			result = multL(result, l, map, preComp);
			
			//get the next max li,j
			if (list.isEmpty())
				break;
			l = list.pop();		
		}
		
		while (len>0){
			len--;
			//Y = Y^2
			result = exponentiate(result, new BigInteger("2"));
			
			while(l.getVal() == len){
				result = multL(result, l, map, preComp);
		
				if (list.isEmpty())
					break;
				l = list.pop();
			}
			
		}
		
		return result;
			
	}*/
	
	/*
	 * fill the list of li,j and the map of ci,j.
	 * The list of li,j contains lValue instances that hold the li,j values 
	 * the map of ci,j contains pair of <key, value>. the key is a string representing the i and j values and the value is the integer ci,j
	 * this function returns the maximum value of li,j
	 */
/*	private int fillListAndMap(BigInteger[] exponentiations, LinkedList<lValue> list, HashMap<String,Integer> map, int n, int w){
		int len = 0; //holds the maximum value of li,j
		ListIterator<lValue> current = null;
		
		for (int i=0; i<n; i++){
			BigInteger exponent = exponentiations[i];
			int l = 0; //holds li,j
			int c = 0; //holds Ci,j
			int numWindows = 0;
			int k = 0; //current index in the window
			boolean startWindow = false;
			
			for (int j=0; j<exponent.bitLength(); j++){
				//starting the window in the first bit that is set
				if (!startWindow && exponent.testBit(j) == true){
					startWindow = true;
					l = j;
				}
				//calculate Ci,j
				if (k < w && startWindow){
					if (exponent.testBit(j) == true){
						c += Math.pow(2, k);
					}
					k++;
					if (k == w){
						putInMap(i, numWindows, c, map);
						current = putInList(i, numWindows, l, list, current);
						k = 0;
						c = 0;
						numWindows++;
						startWindow = false;
					}
				} 
			}
			if (startWindow){
				putInMap(i, numWindows, c, map);
				putInList(i, numWindows, l, list, current);
				
			}
			
			if (len < l){
				len = l;
			}
			current = list.listIterator(list.size());
		}

		return len;
	}
	
	private GroupElement[][] createWUPreCompTable(GroupElement[] groupElements, int w, int n){
		//create the pre-computation table of size n*(2^(w-1)+1)
		int twoPowW = (int) (Math.pow(2, w-1));
		GroupElement[][] preComp = new GroupElement[n][twoPowW + 1];
		GroupElement temp = null;
		for (int i=0; i<n; i++){
			preComp[i][1] = groupElements[i];
			temp = exponentiate(groupElements[i], new BigInteger("2"));
			
			for (int j=2; j<=twoPowW; j++){
				preComp[i][j] = multiplyGroupElements(preComp[i][j-1], temp);
			}
		}
		
		return preComp;
	}
	
	
	private GroupElement multL(GroupElement result, lValue l, HashMap<String,Integer> map, GroupElement[][] preComp){
		int i = l.getI();
		String key = Integer.toString(i) + " " + Integer.toString(l.getJ());
		Integer c = map.get(key);
		int j = (c + 1) / 2;
		result = multiplyGroupElements(result, preComp[i][j]);
		
		return result;
	}
	
	private ListIterator<lValue> putInList(int i, int j, int l, LinkedList<lValue> list, ListIterator<lValue> current){
		lValue lij = new lValue(i, j, l);
		boolean add = false;
		int size = list.size();
		//if this is the first element in the list, add it and set the iterator to point on it
		if (size == 0){
			list.add(lij);
			current = list.listIterator(); 
		} else {
			//while there is a previous element that is smaller than this element, go back in the list.
			//when you find an element that is bigger than this element, add this element after it.
			//set the current iterator to point at the inserted element
			while (current.hasPrevious() && !add){
				int preIndex = current.previousIndex();
				if (lij.compareTo(current.previous()) < 0){
					current.next();
					current.add(lij);
					current = list.listIterator(preIndex + 1);
					add = true;
				}
			}
			//if this element is bigger than all the elements in the list, put it at the beginning and set the iterator to point on it
			if (add == false){
				list.addFirst(lij);
				current = list.listIterator(); 
			}
		}
		return current;
	}
	
	private void putInMap(int i, int j, int c, HashMap<String,Integer> map){
		String ijKey = Integer.toString(i) + " " + Integer.toString(j);
		map.put(ijKey, c);
	}
	*/
	/*
	 * 
	 * @param t
	 * @return
	 */
	/*private int getWUW(int t){
		int w;
		//choose w according to the value of t
		if (t <= 24){
			w = 2;
		} else if (t <= 80){
			w = 3;
		} else if (t <= 240){
			w = 4;
		} else if (t <= 672){
			w = 5;
		} else if (t <= 1792){
			w = 6;
		} else {
			w = 7;
		}
		return w;
	}
	
	private class lValue {
		private int i;
		private int j;
		private int val;
		
		lValue(int i, int j, int val){
			this.i = i;
			this.j = j;
			this.val = val;
		}
		
		public int getI(){
			return i;
		}
		
		public int getJ(){
			return j;
		}
		
		public int getVal(){
			return val;
		}
		
		public int compareTo(lValue second){
			int secondVal = second.getVal();
			if (val > secondVal)
				return 1;
			if (val < secondVal)
				return -1;
			else return 0;
		}
	}
	/*
	 * Computes the product of several exponentiations of the same base
	 * and distinct exponents. 
	 * An optimization is used to compute it more quickly by keeping in memory 
	 * the result of h1, h2, h4,h8,... and using it in the calculation.<p>
	 * Note that if we want a one-time exponentiation of h it is preferable to use the basic exponentiation function 
	 * since there is no point to keep anything in memory if we have no intention to use it. 
	 * @param groupElement
	 * @param exponent
	 * @return the exponentiation result
	 */
	public GroupElement exponentiateWithPreComputedValues
					(GroupElement groupElement, BigInteger exponent){
		
		//extracts from the map the GroupElementsExponentiations object corresponding to the accepted base
		GroupElementsExponentiations exponentiations = exponentiationsMap.get(groupElement);
	
		// if there is no object matches this base - creates it and add it to the map
		if (exponentiations == null){
			exponentiations = new GroupElementsExponentiations(groupElement);
			exponentiationsMap.put(groupElement, exponentiations);
		}
		//calculates the required exponent 
		return exponentiations.getExponentiation(exponent);
		
	}
	
	/**
	 * The class GroupElementExponentiations is a nested class of DlogGroupAbs.
	 * It performs the actual work of exponentially multiple exponentiations for one base.
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
			//build new vactor of exponentiations
			exponentiations = new Vector<GroupElement>();
			exponentiations.add(0, base); //add the base - base^1
			for (int i=1; i<4; i++){
				GroupElement multI;
				multI = exponentiate(exponentiations.get(i-1), new BigInteger("2"));
					
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
			//find the the closest power 2 exponent 
			int index = size.bitLength()-1; 
			
			GroupElement exponent = null;
			/* if the requested index out of the vector bounds, the exponents have not been calculated yet, so calculates them.*/
			if (exponentiations.size()<= index)
				prepareExponentiations(size);
			
			exponent = exponentiations.get(index); //get the closest exponent in the exponentiations vector
			/* if size is not power 2, calculates the additional multiplications */
			BigInteger lastExp = new BigInteger("2").pow(index);
			BigInteger difference = size.subtract(lastExp);
			if (difference.compareTo(BigInteger.ZERO) > 0){
				GroupElement diff = getExponentiation(size.subtract(lastExp));
				exponent = multiplyGroupElements(diff, exponent);
			}
			
			return exponent;		
		}
	}
	
	
}
