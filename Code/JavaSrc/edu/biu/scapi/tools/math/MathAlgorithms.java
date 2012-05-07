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
}
