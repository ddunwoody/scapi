package edu.biu.scapi.securityLevel;
/**
 * Every cryptographic entity has a specific security level. The security level can be specified by making the implementing class<p>
 * of the entity declare that it implements a certain security level, for example some encryption scheme that has CCA security level <p>
 * will implement the Cca interface.<p>
 * This family of interfaces are marker interfaces that define types of security level and do not have any functionality. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface SecurityLevel {

}
