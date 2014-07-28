Coin Tossing
============

The basic case of coin tossing is the practice of throwing a coin in the air to choose between two alternatives, sometimes to resolve a dispute between two parties.
The "coin" in our implementation can be various data types, like a bit or a byte array.
Each implementation achieves different security levels.

The general structure of Coin Tossing protocols contains two levels:

* PartyOne and PartyTwo interfaces
* PartyOne and PartyTwo concrete classes for each coin tossing implementation.

.. contents::

Coin Tossing Interfaces
-----------------------

The only function in the coin tossing interfaces (both party one, and party two) is the ``toss()`` function. This function executes the coin tossing protocol and returns a :java:ref:`CTOutput` object. :java:ref:`CTOutput` is a marker interface for the tossed "coin". For each concrete coin type we should implement a dedicated class which will be returned. For example, Blum protocol tosses a single bit, therefore, :java:ref:`CTBlumPartyOne` and :java:ref:`CTBlumPartyTwo` return :java:ref:`CTBitOutput` object as the output of the toss function.

CTPartyOne
~~~~~~~~~~

.. java:type:: public interface CTPartyOne
   :package: edu.biu.scapi.interactiveMidProtocols.coinTossing

   Coin tossing is the practice of throwing a coin in the air to choose between two alternatives, sometimes to resolve a dispute between two parties.
   This is a general interface plays as party one of a coin tossing protocol.
   Each concrete party one class of a coin tossing protocol should implement this interface.

.. java:method:: public CTOutput toss() throws IOException, CommitValueException, CheatAttemptException, ClassNotFoundException
   :outertype: CTPartyOne

   Executes party one role of this coin tossing protocol.

   :throws CheatAttemptException: if party one suspects that party two is trying to cheat.
   :throws ClassNotFoundException: if there was a problem in the serialization mechanism
   :throws IOException: can occur in the commit phase.
   :throws CommitValueException: can occur in case the protocol uses an ElGamal committer.
   :return: CTOutput contains the tossed "coin".

CTPartyTwo
~~~~~~~~~~

.. java:type:: public interface CTPartyTwo
   :package: edu.biu.scapi.interactiveMidProtocols.coinTossing

   Coin tossing is the practice of throwing a coin in the air to choose between two alternatives, sometimes to resolve a dispute between two parties.
   This is a general interface plays as party two of a coin tossing protocol.
   Each concrete party two class of a coin tossing protocol should implement this interface.

.. java:method:: public CTOutput toss() throws ClassNotFoundException, IOException, CheatAttemptException, CommitValueException
   :outertype: CTPartyTwo

   Executes party two role of this coin tossing protocol.

   :throws CheatAttemptException: if party one suspects that party two is trying to cheat.
   :throws ClassNotFoundException: if there was a problem in the serialization mechanism
   :throws IOException: can occur in the commit phase.
   :throws CommitValueException: can occur in case the protocol uses an ElGamal receiver.
   :return: CTOutput contains the tossed "coin".

CTOutput
~~~~~~~~

.. java:type:: public interface CTOutput
   :package: edu.biu.scapi.interactiveMidProtocols.coinTossing

   Each coin tossing protocol outputs different "coin". It can be a single bit, a string, etc. Each concrete output class should implement this interface.

.. java:method:: public Object getOutput()
   :outertype: CTOutput

   Returns the output of the coin tossing protocol.
   The tossed value of the Coin Tossing protocol can vary. Returns Object instance to enable any return value.

   :return: the tossed output.

Implementations in Scapi
------------------------

Concrete Coin Tossing protocols implemented so far are:

* Coin Tossing of a single bit (Blum)
* Coin Tossing of a String
* Semi-Simulatable Coin-Tossing of a String

