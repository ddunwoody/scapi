Layer 3: Interactive Protocols
==============================

The Interactive Protocol layer contains interactive protocols which can be used as a standalone protocols or as building blocks of higher cryptographic schemes. 
The protocols in this layer are two-party protocols, meaning that there are two participants in the protocol execution when each one has a different role. For example, OT protocol consists of a sender and a receiver, ZK protocol consists of a prover and a verifier, etc. The communication between the parties is done through the SCAPI's Communication Layer.

This layer contains the following components:

.. toctree::
   :maxdepth: 2

   interactive_layer/ot
   interactive_layer/sigma_protocols
   interactive_layer/zk
   interactive_layer/commitments
   interactive_layer/coin_tossing
