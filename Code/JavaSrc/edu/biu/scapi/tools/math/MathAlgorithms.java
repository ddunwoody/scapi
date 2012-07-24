/**
 * 
 */
package edu.biu.scapi.tools.math;

import java.math.BigInteger;
import java.util.Vector;

/**
 * This class holds general math algorithms needed by cryptographic algorithms.<p>
 * Each algorithm is represented by a static function that can be called independently from the other algorithms. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class MathAlgorithms {
	
	  /**
     * Computes the integer x that is expressed through the given primes and the
     * congruences with the chinese remainder theorem (CRT).
     * 
     * @param congruences
     *            the congruences c_i
     * @param primes
     *            the primes p_i
     * @return an integer x for that x % p_i == c_i
     */
    public static BigInteger chineseRemainderTheorem(Vector<BigInteger> congruences, Vector<BigInteger> moduli)
    {
        BigInteger retval = BigInteger.ZERO;
        BigInteger all = BigInteger.ONE;
        for (int i = 0; i < moduli.size(); i++)
        {
            all = all.multiply((BigInteger)moduli.elementAt(i));
        }
        for (int i = 0; i < moduli.size(); i++)
        {
            BigInteger a = (BigInteger)moduli.elementAt(i);
            BigInteger b = all.divide(a);
            BigInteger b_ = b.modInverse(a);
            BigInteger tmp = b.multiply(b_);
            tmp = tmp.multiply((BigInteger)congruences.elementAt(i));
            retval = retval.add(tmp);
        }

        return retval.mod(all);
    }
    
    /**
     * Computes n!  (n factorial)
     * @param n
     * @return n!
     */
    public static int factorial(int n) { 
        int fact = 1; // this  will be the result 
        for (int i = 1; i <= n; i++) { 
            fact *= i; 
        } 
        return fact; 
    } 

    /**
     * Computes n!  (n factorial)
     * @param n
     * @return n! as a BigInteger
     */
    public static BigInteger factorialBI(int n) { 
        BigInteger fact = BigInteger.ONE; // this  will be the result 
        for (int i = 1; i <= n; i++) { 
            //fact *= i;
        	fact = fact.multiply(BigInteger.valueOf(i));
        } 
        return fact; 
    } 
    
    /*-------------------------------------------------------------*/
    /**
     * This class holds the result of calculating the square root of a BigInteger.
     * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
     *
     */
    public static class SquareRootResults{
    	BigInteger root1;
    	BigInteger root2;
		public SquareRootResults(BigInteger root1, BigInteger root2) {
			super();
			this.root1 = root1;
			this.root2 = root2;
		}
		public BigInteger getRoot1() {
			return root1;
		}
		public BigInteger getRoot2() {
			return root2;
		}
    	
    }		
		
    /**
     * This function calculates the square root of z mod p if and only if p is a prime such that p = 3 mod 4.
     * This function assumes that p is a prime and does not perform the primality check for efficiency reasons. 
     * @param z the number for which we calculate the square root
     * @param p the mod
     * @throws IllegalArgumentException if p != 3 mod 4
     * @return SquareRootResults which is a pair of BigIntegers x and -x such that z = x^2  and z = -x^2 
     */
	public  static SquareRootResults sqrtModP_3_4(BigInteger z, BigInteger p){
		//We assume here (and we do not check for efficiency reasons) that p is a prime
		//We do check that the prime p = 3 mod 4, if not throw exception 
		BigInteger four = BigInteger.valueOf(4); 
		if(!p.mod(four).equals(BigInteger.valueOf(3)))
			throw new IllegalArgumentException("p has to be a prime such that p = 3 mod 4");
		
		BigInteger exponent = p.add(BigInteger.ONE).divide(four);
		BigInteger x =  z.modPow(exponent, p);
		return new SquareRootResults(x, x.negate().mod(p));
    }
	
	/*-------------------------------------------------------------*/
}
