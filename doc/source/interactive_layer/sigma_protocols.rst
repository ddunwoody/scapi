Sigma Protocols
===============

**Sigma Protocols** are a basic building block for Zero-knowledge proofs, Zero-Knowledge Proofs Of Knowledge and more. A sigma protocol is a 3-round proof, comprised of:

1. A first message from the prover to the verifier
2. A random challenge from the verifier
3. A second message from the prover.

Sigma Protocol can be executed as a standalone protocol or as a building block for another protocol, like Zero Knowledge proofs.
As a standalone protocol, Sigma protocol should execute the protocol as is, including the communication between the prover and the verifier.
As a building block for other protocols, Sigma protocol should only compute the prover's first and second messages and the verifier's challenge and verification. This is, in other words, the protocol functions without communication between the parties.

To enable both options, there is a separation between the communication part and the actual protocol computations.
The general structure of Sigma Protocol contains the following components:

* Prover, Verifier and Simulator generic interfaces.
* Prover and Verifier abstract classes.
* ProverComputation and VerifierComputation classes (Specific to each protocol).

.. contents::

The Prover Interface
--------------------

The :java:ref:`SigmaProtocolProver` interface has two modes of operation:

1. Explicit mode - call processFirstMessage() to process the first message and afterwards call processSecondMessage() to process the second message.

2. Implicit mode - Call prove() function that calls the above two functions. This way is more easy to use since the user should not be aware of the order in which the functions must be called.

.. java:type:: public interface SigmaProtocolProver
   :package: edu.biu.scapi.interactiveMidProtocols.sigmaProtocol

   General interface for Sigma Protocol prover. Every class that implements it is signed as Sigma Protocol prover.
   Sigma protocols are a basic building block for zero-knowledge, zero-knowledge proofs of knowledge and more.

   A sigma protocol is a 3-round proof, comprised of a first message from the prover to the verifier, a random challenge from the verifier and a second message from the prover.
   See Hazay-Lindell (chapter 6) for more information.

.. java:method:: public void processFirstMsg(SigmaProverInput input) throws IOException
   :outertype: SigmaProtocolProver

   Processes the first step of the sigma protocol.
   It computes the first message and sends it to the verifier.

   :param input:
   :throws IOException: if failed to send the message.

.. java:method:: public void processSecondMsg() throws CheatAttemptException, IOException, ClassNotFoundException
   :outertype: SigmaProtocolProver

   Processes the second step of the sigma protocol.
   It receives the challenge from the verifier, computes the second message and then sends it to the verifier.

   **This is a blocking function!**

   :throws CheatAttemptException: if the received challenge's length is not equal to the soundness parameter.
   :throws IOException: if there was a problem during the communication phase.
   :throws ClassNotFoundException: if there was a problem during the serialization mechanism.

.. java:method:: public void prove(SigmaProverInput input) throws CheatAttemptException, IOException, ClassNotFoundException
   :outertype: SigmaProtocolProver

   Runs the proof of this protocol.

   This function executes the proof at once by calling the above functions one by one.
   This function can be called when a user does not want to save time by doing operations in parallel.

   :param input:
   :throws CheatAttemptException: if the received challenge's length is not equal to the soundness parameter.
   :throws IOException: if there was a problem during the communication phase.
   :throws ClassNotFoundException: if there was a problem during the serialization mechanism.

The Verifier Interface
----------------------

The :java:ref:`SigmaProtocolVerifier` also has two modes of operation:

1. Explicit mode – call sampleChallenge() to sample the challenge, then sendChallenge() to receive the prover's first message and then call processVerify() to receive the prover's second message and verify the proof.

2. Implicit mode - Call verify() function that calls the above three functions. Same as the prove function of the prover, this way is much simpler, since the user should not know the order of the functions.

.. java:type:: public interface SigmaProtocolVerifier
   :package: edu.biu.scapi.interactiveMidProtocols.sigmaProtocol

   General interface for Sigma Protocol verifier. Every class that implements it is signed as Sigma Protocol verifier.

.. java:method:: public byte[] getChallenge()
   :outertype: SigmaProtocolVerifier

   Returns the sampled challenge.

   :return: the challenge.

.. java:method:: public boolean processVerify(SigmaCommonInput input) throws ClassNotFoundException, IOException
   :outertype: SigmaProtocolVerifier

   Waits to the prover's second message and then verifies the proof.
   **This is a blocking function!**

   :param input:
   :throws ClassNotFoundException: if there was a problem during the serialization mechanism.
   :throws IOException: if there was a problem during the communication phase.
   :return: true if the proof has been verified; false, otherwise.

.. java:method:: public void sampleChallenge()
   :outertype: SigmaProtocolVerifier

   Samples the challenge for this protocol.

.. java:method:: public void sendChallenge() throws IOException, ClassNotFoundException
   :outertype: SigmaProtocolVerifier

   Waits for the prover's first message and then sends the chosen challenge to the prover.
   **This is a blocking function!**

   :throws ClassNotFoundException: if there was a problem during the serialization mechanism.
   :throws IOException: if there was a problem during the communication phase.

.. java:method:: public void setChallenge(byte[] challenge)
   :outertype: SigmaProtocolVerifier

   Sets the given challenge.

   :param challenge:

.. java:method:: public boolean verify(SigmaCommonInput input) throws ClassNotFoundException, IOException
   :outertype: SigmaProtocolVerifier

   Runs the verification of this protocol.

   This function executes the verification protocol at once by calling the following functions one by one.
   This function can be called when a user does not want to save time by doing operations in parallel.

   :param input:
   :throws ClassNotFoundException: if there was a problem during the serialization mechanism.
   :throws IOException: if there was a problem during the communication phase.
   :return: true if the proof has been verified; false, otherwise.

The Simulator Interface
-----------------------

The :java:ref:`SigmaSimulator` has two simulate() functions. Both functions simulate the sigma protocol. The difference between them is the source of the challenge; one function receives the challenge as an input argument, while the other samples a random challenge. Both simulate functions return :java:ref:`SigmaSimulatorOutput` object that holds the simulated a, e, z.

.. java:type:: public interface SigmaSimulator
   :package: edu.biu.scapi.interactiveMidProtocols.sigmaProtocol

   General interface for Sigma Protocol Simulator. The simulator is a probabilistic polynomial-time function, that on input x and challenge e outputs a transcript of the form (a, e, z) with the same probability distribution as transcripts between the honest prover and verifier on common input x.

.. java:method:: public int getSoundnessParam()
   :outertype: SigmaSimulator

   Returns the soundness parameter for this Sigma simulator.

   :return: t soundness parameter

.. java:method:: public SigmaSimulatorOutput simulate(SigmaCommonInput input, byte[] challenge) throws CheatAttemptException
   :outertype: SigmaSimulator

   Computes the simulator computation.

   :param input:
   :param challenge:
   :throws CheatAttemptException: if the received challenge's length is not equal to the soundness parameter.
   :return: the output of the computation - (a, e, z).

.. java:method:: public SigmaSimulatorOutput simulate(SigmaCommonInput input)
   :outertype: SigmaSimulator

   Chooses random challenge and computes the simulator computation.

   :param input:
   :return: the output of the computation - (a, e, z).

Computation classes
-------------------

The classes that operate the **actual** protocol phases implement the :java:ref:`SigmaProverComputation` and :java:ref:`SigmaVerifierComputation` interfaces. SigmaProverComputation computes the prover's messages and SigmaVerifierComputation computes the verifier's challenge and verification. Each operation is done in a dedicated function.

In case that Sigma Protocol is used as a building block, the protocol which uses it will hold an instance of SigmaProverComputation or SigmaVerifierComputation and will call the required function. Each concrete sigma protocol should implement the computation interfaces.

SigmaProverComputation
~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public interface SigmaProverComputation
   :package: edu.biu.scapi.interactiveMidProtocols.sigmaProtocol

   This interface manages the mathematical calculations of the prover side in the sigma protocol.
   It samples random values and computes the messages.

.. java:method:: public SigmaProtocolMsg computeFirstMsg(SigmaProverInput input)
   :outertype: SigmaProverComputation

   Computes the first message of the sigma protocol.

   :param input:

.. java:method:: public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException
   :outertype: SigmaProverComputation

   Computes the second message of the sigma protocol.

   :throws CheatAttemptException: if the received challenge's length is not equal to the soundness parameter.

SigmaVerifierComputation
~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public interface SigmaVerifierComputation
   :package: edu.biu.scapi.interactiveMidProtocols.sigmaProtocol

   This interface manages the mathematical calculations of the verifier side in the sigma protocol.
   It samples random challenge and verifies the proof.

.. java:method:: public void sampleChallenge()
   :outertype: SigmaVerifierComputation

   Samples the challenge for this protocol.

.. java:method:: public void setChallenge(byte[] challenge)
   :outertype: SigmaVerifierComputation

   Sets the given challenge.

   :param challenge:

.. java:method:: public byte[] getChallenge()
   :outertype: SigmaVerifierComputation

   Returns the sampled challenge.

   :return: the challenge.

.. java:method:: public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z)
   :outertype: SigmaVerifierComputation

   Verifies the proof.

   :param input:
   :return: true if the proof has been verified; false, otherwise.

Supported Protocols
-------------------

Concrete Sigma protocols implemented so far are:

* Dlog
* DH
* Extended DH
* Pedersen commitment knowledge
* Pedersen committed value
* El Gamal commitment knowledge
* El Gamal committed value
* El Gamal private key
* El Gamal encrypted value
* Cramer-Shoup encrypted value
* Damgard-Jurik encrypted zero
* Damgard-Jurik encrypted value
* Damgard-Jurik product
* AND (of multiple statements)
* OR of two statements
* OR of multiple statements

Example of Usage
----------------

Steps in prover creation:

* Given a :java:ref:`Channel` object channel and input for the concrete Sigma protocol prover (In the example below, x and h) do:

  * Create a :java:ref:`SigmaProverComputation` (for example, :java:ref:`SigmaDlogProverComputation`).
  * Create a :java:ref:`SigmaProtocolProver` with channel and the proverComputation.
  * Create input object for the prover. 
  * Call the ``prove()`` function of the prover with the input.

Prover code example:

.. code-block:: java

    //Creates the dlog group.
    DlogGroup dlog = null;
    try {
        //use the koblitz curve.
        dlog = new MiraclDlogECF2m("K-233");
    } catch (FactoriesException e1) {
        // TODO Auto-generated catch block
        e1.printStackTrace();
    }

    //Creates sigma prover computation.
    SigmaProverComputation proverComputation = new SigmaDlogProverComputation(dlog, t, new SecureRandom());

    //Create Sigma Prover with the given SigmaProverComputation.
    SigmaProver prover = new SigmaProver(channel, proverComputation); 
    
    //Creates input for the prover.
    SigmaProverInput input = new SigmaDlogProverInput(h, w);
    
    //Calls the prove function of the prover.
    prover.prove(input);

Steps in verifier creation:

* Given a :java:ref:`Channel` object channel and input for the concrete Sigma protocol verifier (In the example below, h) do:

  * Create a :java:ref:`SigmaVerifierComputation` (for example, :java:ref:`SigmaDlogVerifierComputation`).
  * Create a :java:ref:`SigmaProtocolVerifier` with channel and verifierComputation.
  * Create input object for the verifier. 
  * Call the ``verify()`` function of the verifier with the input.

Verifier code example:

.. code-block:: java

    //Creates the dlog group
    DlogGroup dlog = null;
    try {
        //use the koblitz curve
        dlog = new MiraclDlogECF2m("K-233");
    } catch (FactoriesException e1) {
        // TODO Auto-generated catch block
        e1.printStackTrace();
    }
    
    //Creates sigma verifier computation.
    SigmaVerifierComputation verifierComputation = new SigmaDlogVerifierComputation(dlog, t, new SecureRandom());
    
    //Creates Sigma verifier with the given SigmaVerifierComputation.
    SigmaVerifier verifier = new SigmaVerifier(channel, verifierComputation);
    
    // Creates input for the verifier.
    SigmaCommonInput input = new SigmaDlogCommonInput(h);
    
    //Calls the verify function of the verifier.
    verifier.verify(input);
