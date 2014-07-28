Oblivious Transfer Protocols
============================

In Oblivious Transfer, a party called **the sender** has :math:`n` messages, and a party called **the receiver** has an index :math:`i`. 
The receiver wishes to receive the :math:`i^{th}` message of the sender, without the sender learning :math:`i`, 
while the sender wants to ensure that the receiver receives only one of the :math:`n` messages.

.. contents::

Class Hierarchy
---------------

The general structure of OT protocols contains three components:

* Sender and Receiver interfaces
* Sender and receiver abstract classes
* Sender and receiver concrete classes

Interfaces
~~~~~~~~~~

Both Sender and Receiver interfaces declare the ``transfer()`` function, which executes the OT protocol. The ``transfer()`` function of the sender runs the protocol from the sender's point of view, while the transfer function of the receiver runs the protocol from the receiver's point of view. 

Both transfer functions accept two parameters:

* A channel that is used to send and receive messages during the protocol execution.
* An input object that holds the required parameter to the sender/receiver execution.

The input types are :java:ref:`OTSInput` and :java:ref:`OTRInput`. These are marker interfaces for the sender's and receiver's input, respectively. 
Each concrete implementation may have some different parameters and should implement a dedicated input class that holds them.
The transfer functions of the sender and the receiver differ in their return value. While the sender's transfer function returns void, the receiver's transfer function returns :java:ref:`OTROutput`, which is a marker interface. Each concrete OT receiver should implement a dedicated output class that holds the necessary output objects.

The OTSender Interface
^^^^^^^^^^^^^^^^^^^^^^

.. java:type:: public interface OTSender
   :package: edu.biu.scapi.interactiveMidProtocols.ot

.. java:method:: public void transfer(Channel channel, OTSInput input) throws IOException, ClassNotFoundException, CheatAttemptException, InvalidDlogGroupException
   :outertype: OTSender

   The transfer stage of OT protocol which can be called several times in parallel.
   The OT implementation support usage of many calls to transfer, with single preprocess execution.
   This way, one can execute batch OT by creating the OT sender once and call the transfer function for each input couple.
   In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages. This way the parallel executions of the function will not block each other.

   :param channel: each call should get a different one.
   :param input: The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
   :throws ClassNotFoundException: if there was a problem in the serialization mechanism.
   :throws IOException: if there was a problem during the communication.
   :throws CheatAttemptException: if the sender suspects that the receiver is trying to cheat.
   :throws InvalidDlogGroupException: if the given DlogGRoup is not valid.

The OTReciever Interface
^^^^^^^^^^^^^^^^^^^^^^^^

.. java:type:: public interface OTReceiver
   :package: edu.biu.scapi.interactiveMidProtocols.ot

.. java:method:: public OTROutput transfer(Channel channel, OTRInput input) throws CheatAttemptException, IOException, ClassNotFoundException
   :outertype: OTReceiver

   The transfer stage of OT protocol which can be called several times in parallel.
   The OT implementation support usage of many calls to transfer, with single preprocess execution.
   This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.
   In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages. This way the parallel executions of the function will not block each other.

   :param channel: each call should get a different one.
   :param input: The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
   :throws CheatAttemptException: if there was a cheat attempt during the execution of the protocol.
   :throws IOException: if the send or receive functions failed
   :throws ClassNotFoundException: if there was a problem during the serialization mechanism
   :return: OTROutput, the output of the protocol.

The Input/Output Interfaces
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. java:type:: public interface OTSInput
   :package: edu.biu.scapi.interactiveMidProtocols.ot

   Every OT sender needs inputs during the protocol execution, but every concrete protocol needs different inputs.
   This interface is a marker interface for OT sender input, where there is an implementing class for each OT protocol.

.. java:type:: public interface OTRInput
   :package: edu.biu.scapi.interactiveMidProtocols.ot

   Every OT receiver needs inputs during the protocol execution, but every concrete protocol needs different inputs.
   This interface is a marker interface for OT receiver input, where there is an implementing class for each OT protocol.

.. java:type:: public interface OTROutput
   :package: edu.biu.scapi.interactiveMidProtocols.ot

   Every OT receiver outputs a result in the end of the protocol execution, but every concrete protocol output different data.
   This interface is a marker interface for OT receiver output, where there is an implementing class for each OT protocol.


Abstract classes
~~~~~~~~~~~~~~~~

Each concrete OT protocol has abstract classes for both sender and receiver. Both classes implement common behavior of sender and receiver, accordingly. Each of the abstract classes implements the corresponding interface (sender/receiver).

Concrete implementations
~~~~~~~~~~~~~~~~~~~~~~~~

As we have already said, each concrete OT implementation should implement dedicated sender and receiver classes. These classes implement the functionalities that are unique for the specific implementation. Most OT protocols can work on two different types of inputs: byte arrays and DlogGroup elements. Each input type should be treated differently, thus we decided to have concrete sender/receiver classes for each input option.

Concrete OT implemented so far are:

* Semi Honest
* Privacy Only
* One Sided Simulation
* Full Simulation
* Full Simulation – ROM
* UC
* Batch Semi Honest
* Batch Semi Honest Extension

Basic Usage
-----------

In order to execute the OT protocol, both sender and receiver should be created as separate programs (Usually not on the same machine). 
The main function in the sender and the receiver is the transfer function, that gets the communication channel between them and input.

Steps in sender creation:

* Given a :java:ref:`Channel` object channel do:
* Create an :java:ref:`OTSender` (for example, :java:ref:`OTSemiHonestDDHOnGroupElementSender`).
* Create input for the sender. Usually, the input for the receiver contains x0 and x1.
* Call the transfer function of the sender with channel and the created input.

.. code-block:: java

    //Creates the OT sender object.
    OTSemiHonestDDHOnGroupElementSender sender = new OTSemiHonestDDHOnGroupElementSender();
    
    //Creates input for the sender. 
    GroupElement x0 = dlog.createRandomElement();
    GroupElement x1 = dlog.createRandomElement();
    OTSOnGroupElementInput input = new OTSOnGroupElementInput(x0, x1);
    
    //call the transfer part of the OT protocol
    try {
        sender.transfer(channel, input);
    } catch (IOException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (ClassNotFoundException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (CheatAttemptException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (InvalidDlogGroupException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }

Steps in receiver creation:

* Given a :java:ref:`Channel` object channel do:
* Create an :java:ref:`OTReceiver` (for example, :java:ref:`OTSemiHonestDDHOnGroupElementReceiver`).
* Create input for the receiver. Usually, the input for the receiver contains only sigma parameter.
* Call the transfer function of the receiver with channel and the created input.

.. code-block:: java

    //Creates the OT receiver object.
    OTSemiHonestDDHOnGroupElementReceiver receiver = new OTSemiHonestDDHOnGroupElementReceiver();
    
    //Creates input for the receiver.
    byte sigma = 1; 
    OTRBasicInput input = new OTRBasicInput(sigma);
    
    OTROutput output = null;
    try {
        output = receiver.transfer(channel, input);
    } catch (CheatAttemptException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (IOException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (ClassNotFoundException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }
    //use output…
