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
package edu.biu.scapi.interactiveMidProtocols.ot.fullSimulationROM;

import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.interactiveMidProtocols.ot.fullSimulation.OTFullSimOnByteArraySenderTransferUtil;
import edu.biu.scapi.interactiveMidProtocols.ot.fullSimulation.OTFullSimPreprocessPhaseValues;
import edu.biu.scapi.interactiveMidProtocols.ot.fullSimulation.OTFullSimSenderPreprocessUtil;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKPOKFiatShamirFromSigmaVerifier;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.randomOracle.RandomOracle;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.securityLevel.Malicious;
import edu.biu.scapi.securityLevel.StandAlone;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;
import edu.biu.scapi.tools.Factories.KdfFactory;
import edu.biu.scapi.tools.Factories.RandomOracleFactory;

/**
 * Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves 
 * full simulation in the random oracle model.<p>
 * 
 * This class derived from OTFullSimROMDDHSenderAbs and implements the functionality 
 * related to the byte array inputs.<p>
 * 
 * For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell; 
 * this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge. <P>
 * 
 * The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTFullSimROMDDHOnByteArraySender implements OTSender, Malicious, StandAlone{
	
	private DlogGroup dlog;
	private SecureRandom random;
	private RandomOracle ro;
	private KeyDerivationFunction kdf; //Used in the calculation.
	
	private OTFullSimPreprocessPhaseValues preprocessOutput; //Values calculated by the preprocess phase.
	
	/**
	 * Constructor that chooses default values of DlogGroup, kdf, randomOracle and SecureRandom.
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	 * @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	 * @throws IOException if there was a problem during the communication in the preprocess phase.
	 * @throws CommitValueException can occur in case of ElGamal commitment scheme.
	 * 
	 */
	public OTFullSimROMDDHOnByteArraySender(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException, CommitValueException {
		//Read the default DlogGroup name from a configuration file.
		String dlogName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		String roName = ScapiDefaultConfiguration.getInstance().getProperty("RandomOracle");
		DlogGroup dlog = null;
		RandomOracle ro = null;
		KeyDerivationFunction kdf = null;
		try {
			//Create the default DlogGroup by the factory.
			dlog = DlogGroupFactory.getInstance().getObject(dlogName);
			//Create the default random oracle by the factory.
			ro = RandomOracleFactory.getInstance().getObject(roName);
			//Create  default kdf by the factory.
			kdf = KdfFactory.getInstance().getObject("HKDF(HMac(SHA-256))");
		} catch (FactoriesException e1) {
			// Should not occur since the dlog name in the configuration file is valid.
		}
		
		
		try {
			doConstruct(channel, dlog, ro, kdf, new SecureRandom());
		} catch (SecurityLevelException e1) {
			// Should not occur since the dlog in the configuration file is as secure as needed.
		} catch (InvalidDlogGroupException e) {
			// Should not occur since the dlog in the configuration file is valid.
		}
				
	}
	
	/**
	 * Constructor that sets the given , dlogGroup, kdf and random.
	 * @param dlog must be DDH secure.
	 * @param kdf
	 * @param ro random oracle
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 * @throws InvalidDlogGroupException if the given dlog is invalid.
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	 * @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	 * @throws IOException if there was a problem during the communication in the preprocess phase.
	 * @throws CommitValueException can occur in case of ElGamal commitment scheme.
	 */
	public OTFullSimROMDDHOnByteArraySender(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf, RandomOracle ro, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException, CommitValueException{
		doConstruct(channel, dlog, ro, kdf, new SecureRandom());
	}
	
	/**
	 * Sets the given members.
	 * @param dlog must be DDH secure.
	 * @param randomOracle
	 * @param random
	 * @throws SecurityLevelException 
	 * @throws InvalidDlogGroupException 
	 * @throws CommitValueException 
	 * @throws CheatAttemptException 
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * 
	 */
	private void doConstruct(Channel channel, DlogGroup dlog, RandomOracle oracle, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException, CommitValueException  {
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		// Runs the following part of the protocol:
		//	IF NOT VALID_PARAMS(G,q,g0)
	    //    REPORT ERROR and HALT.
	    
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();

		this.dlog = dlog;
		this.random = random;
		this.kdf = kdf;
		this.ro = oracle;
		
		//read the default statistical parameter used in sigma protocols from a configuration file.
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
		
		//Create the underlying ZKPOK
		ZKPOKFiatShamirFromSigmaVerifier zkVerifier = new ZKPOKFiatShamirFromSigmaVerifier(channel, new SigmaDHVerifierComputation(dlog, t, random), ro);
		
		// Some OT protocols have a pre-process stage before the transfer. 
		// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
		// and then the transfer function could be called multiple times.
		// We implement the preprocess stage at construction time. 
		// A protocol that needs to call preprocess after the construction time, should create a new instance.
		//Call the utility function that executes the preprocess phase.
		preprocessOutput = OTFullSimSenderPreprocessUtil.preProcess(channel, dlog, zkVerifier);
	}

	/**
	 * Runs the transfer phase of the protocol.<p>
	 *	Transfer Phase (with inputs x0,x1)<p>
	 *		WAIT for message from R<p>
	 *		DENOTE the values received by (g,h) <p>
	 *		COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
	 *		COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
	 *		COMPUTE c0 = x0 XOR KDF(|x0|,v0)<p>
	 *		COMPUTE c1 = x1 XOR KDF(|x1|,v1)<p>
	 *		SEND (u0,c0) and (u1,c1) to R<p>
	 *		OUTPUT nothing<p>
	 */
	public void transfer(Channel channel, OTSInput input) throws IOException, ClassNotFoundException{
		//Creates the utility class that executes the transfer phase.
		OTFullSimOnByteArraySenderTransferUtil transferUtil = new OTFullSimOnByteArraySenderTransferUtil(dlog, kdf, random);
		transferUtil.transfer(channel, input, preprocessOutput);
		
	}
}
