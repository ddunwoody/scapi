Zero Knowledge Proofs and Zero Knowledge Proofs of Knowledge
============================================================

A **zero-knowledge proof** or a zero-knowledge protocol is a method by which one party (the prover) can prove to another party (the verifier) that a given statement is true, without conveying any additional information apart from the fact that the statement is indeed true. A **zero-knowledge proof of knowledge (ZKPOK)** is a sub case of zero knowledge proofs, in which the prover proves to the verifier that he knows how to prove a statement, without actually proving it.

.. contents::

Zero Knowledge Interfaces
-------------------------

ZKProver
~~~~~~~~

The :java:ref:`ZKProver` interface declares the ``prove()`` function that accepts an input and runs the ZK proof. The input type is :java:ref:`ZKProverInput`, which is a marker interface. Every concrete protocol should have a dedicated input class that implements it.

.. java:type:: public interface ZKProver
   :package: edu.biu.scapi.interactiveMidProtocols.zeroKnowledge

   A zero-knowledge proof or zero-knowledge protocol is a method by which one party (the prover) can prove to another party (the verifier) that a given statement is true, 
   without conveying any additional information apart from the fact that the statement is indeed true.

   This interface is a general interface that simulates the prover side of the Zero Knowledge proof. Every class that implements it is signed as Zero Knowledge prover.

.. java:method:: public void prove(ZKProverInput input) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException
   :outertype: ZKProver

   Runs the prover side of the Zero Knowledge proof.

   :param input: holds necessary values to the proof calculations.
   :throws CheatAttemptException: if the prover suspects the verifier is trying to cheat.
   :throws IOException: if there was a problem during the communication.
   :throws ClassNotFoundException: if there was a problem during the serialization mechanism.
   :throws CommitValueException: can occur when using ElGamal commitment scheme.

ZKVerifier
~~~~~~~~~~

The :java:ref:`ZKVerifier` interface declares the ``verify()`` function that accepts an input and runs the ZK proof verification. The input type is :java:ref:`ZKCommonInput`, which is a marker interface of inputs that are common for the prover and the verifier. Every concrete protocol should have a dedicated input class that implements it.

.. java:type:: public interface ZKVerifier
   :package: edu.biu.scapi.interactiveMidProtocols.zeroKnowledge

   A zero-knowledge proof or zero-knowledge protocol is a method by which one party (the prover) can prove to another party (the verifier) that a given statement is true, 
   without conveying any additional information apart from the fact that the statement is indeed true.

   This interface is a general interface that simulates the verifier side of the Zero Knowledge proof. Every class that implements it is signed as Zero Knowledge verifier.

.. java:method:: public boolean verify(ZKCommonInput input) throws IOException, ClassNotFoundException, CommitValueException, CheatAttemptException
   :outertype: ZKVerifier

   Runs the verifier side of the Zero Knowledge proof.

   :param input: holds necessary values to the varification calculations.
   :throws CheatAttemptException: if the prover suspects the verifier is trying to cheat.
   :throws IOException: if there was a problem during the communication.
   :throws ClassNotFoundException: if there was a problem during the serialization mechanism.
   :throws CommitValueException: can occur when using ElGamal commitment scheme.
   :return: true if the proof was verified; false, otherwise.

ZKProverInput
~~~~~~~~~~~~~

.. java:type:: public interface ZKProverInput
   :package: edu.biu.scapi.interactiveMidProtocols.zeroKnowledge

   Marker interface. Each concrete ZK prover's input class should implement this interface.

ZKCommonInput
~~~~~~~~~~~~~

.. java:type:: public interface ZKCommonInput
   :package: edu.biu.scapi.interactiveMidProtocols.zeroKnowledge

   This interface is a marker interface for Zero Knowledge input, where there is an implementing class for each concrete Zero Knowledge protocol.

Zero Knowledge Proof of Knowledge Interfaces
--------------------------------------------

:java:ref:`ZKPOKProver` and :java:ref:`ZKPOKVerifier` are marker interfaces that extend the :java:ref:`ZKProver` and :java:ref:`ZKVerifier` interfaces. ZKPOK concrete protocol should implement these marker interfaces instead of the general ZK interfaces.

.. java:type:: public interface ZKPOKProver extends ZKProver
   :package: edu.biu.scapi.interactiveMidProtocols.zeroKnowledge

   This interface is a general interface that simulates the prover side of the Zero Knowledge proof of knowledge.
   Every class that implements it is signed as ZKPOK prover.

.. java:type:: public interface ZKPOKVerifier extends ZKVerifier
   :package: edu.biu.scapi.interactiveMidProtocols.zeroKnowledge

   This interface is a general interface that simulates the verifier side of the Zero Knowledge proof of knowledge.
   Every class that implements it is signed as ZKPOK verifier.

Implemented Protocols
---------------------

Concrete Zero Knowledge protocols implemented so far are:

* Zero Knowledge from any sigma protocol
* Zero Knowledge Proof of Knowledge from any sigma protocol (currently implemented using Pedersen Commitment scheme)
* Zero Knowledge Proof of Knowledge from any sigma protocol Fiat Shamir (Random Oracle Model)

Example of Usage
----------------

Steps in prover creation:

* Given a Channel object channel and input for the underlying SigmaProverComputation (in the following case, h and x) do:

  * Create a SigmaProverComputation (for example, SigmaDlogProverComputation).
  * Create a ZKProver with channel and the proverComputation (ForExample, ZKFromSigmaProver).
  * Create input object for the prover.
  * Call the prove function of the prover with the input.

Prover code example:

.. code-block:: java

    try {
        //create the ZK prover
        DlogGroup dlog = new MiraclDlogECF2m("K-233");
        ZKProver prover = new ZKFromSigmaProver(channel, new SigmaDlogProverComputation(dlog, 40, new SecureRandom()));
    
        //create the input for the prover
        SigmaDlogProverInput input = new SigmaDlogProverInput(h, x);
        
        //Call prove function
        prover.prove(input);
    
    } catch (IllegalArgumentException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (IOException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (CheatAttemptException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (ClassNotFoundException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (CommitValueException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }

Steps in verifier creation:

* Given a Channel object channel and input for the underlying SigmaVerifierComputation (In the example below, h) do:

  * Create a SigmaVerifierComputation (for example, SigmaDlogVerifierComputation).
  * Create a ZKVerifier with channel and verifierComputation (For example, ZKFromSigmaVerifier).
  * Create input object for the verifier. 
  * Call the verify function of the verifier with the input.

Verifier code example:

.. code-block:: java

    try {
        //create the ZK verifier
        DlogGroup dlog = new MiraclDlogECF2m("K-233");
        ZKVerifier verifier = new ZKFromSigmaVerifier(channel, new SigmaDlogVerifierComputation(dlog, 40, new SecureRandom()), new SecureRandom());
    
        //create the input for the verifier
        SigmaDlogCommonInput input = new SigmaDlogCommonInput(h);
        //Call verify function
        System.out.println(verifier.verify(input));
        
    } catch (IllegalArgumentException e) {
        // TODO Auto-generated catch block
	e.printStackTrace();
    } catch (IOException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (CheatAttemptException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (ClassNotFoundException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (CommitValueException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (InvalidDlogGroupException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }
