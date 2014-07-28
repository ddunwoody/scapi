The Communication Layer
=======================

The communication layer provides communication services to any interactive cryptographic protocol. It uses cryptographic tools such as digital signatures and encryption in order to provide secure and private channels. This layer is heavily used by the interactive protocols in SCAPI’s third layer and by MPC protocols. It can also be used by any other cryptographic protocol that requires communication.

All the classes in the Communication Layer belong to the package ``edu.biu.scapi.comm``.

.. contents::

Fetch the list of parties from a properties file
------------------------------------------------

The first thing that needs to be done to obtain communication services is to setup the connections between the different parties. Each party needs to run the setup process at the end of which the established connections are obtained. The established connections are called *channels*. The list of parties and their addresses are usually obtained from a Properties file. For example, here is a properties file called *Parties0.properties*: ::

    # A configuration file for the parties

    NumOfParties = 2

    IP0 = 127.0.0.1
    IP1 = 127.0.0.1

    Port0 = 8001
    Port1 = 8000

In order to read this file, we can use the ``LoadParties`` class:

.. code-block:: java

    import edu.biu.scapi.comm.Party;
    import edu.biu.scapi.comm.LoadParties;
    
    LoadParties loadParties = new LoadParties("Parties0.properties");
    List<Party> listOfParties = loadParties.getPartiesList();

Each party is represented by an instance of the ``Party`` class. A ``List<Party>`` object is required in the `communication setup phase`_.

.. _`communication setup phase`:

Setup communication to other parties
------------------------------------

The ``CommunicationSetup`` Class is responsible for establishing secure communication to other parties. An application requesting from ``CommunicationSetup`` to prepare for communication needs to call the ``CommunicationSetup::prepareForCommunication()`` function:

.. java:type:: public class CommunicationSetup implements TimeoutObserver
    :package: edu.biu.scapi.comm

    CommunicationSetup implements the org.apache.commons.exec.TimeoutObserver interface. This interface supplies a mechanism for notifying classes that a timeout has arrived.

.. java:method:: Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties, ConnectivitySuccessVerifier successLevel, long timeOut, boolean enableNagle)
    :outertype: CommunicationSetup

    :param List<Party> listOfParties: The list of parties to connect to. As a convention, we will set the first party in the list to be the requesting party, that is, the party represented by the application.
    :param ConnectivitySuccessVerifier successLevel: The type of `connecting success`_ required.
    :param long timeOut: A time-out (in milliseconds) specifying how long to wait for connections to be established and secured.
    :param boolean enableNagle: Whether or not `Nagle’s algorithm <http://en.wikipedia.org/wiki/Nagle's_algorithm>` can be enabled.
    :return: a map of the established channels.

Here is an example on how to use the `CommunicationSetup` class, we leave the discussion about the `ConnectivitySuccessVerifier` instance to the next section.

.. code-block:: java

    import java.net.InetSocketAddress;
    import java.util.List;
    import java.util.Map;

    import edu.biu.scapi.comm.Party;
    import edu.biu.scapi.comm.LoadParties;

    import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.comm.CommunicationSetup;

    import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
    import edu.biu.scapi.comm.NaiveSuccess;

    //Prepare the parties list.
    LoadParties loadParties = new LoadParties("Parties0.properties");
    List<Party> listOfParties = loadParties.getPartiesList();
    
    //Create the communication setup.
    CommunicationSetup commSetup = new CommunicationSetup();
    
    //Choose the naive connectivity success algorithm.
    ConnectivitySuccessVerifier naive = new NaiveSuccess();
    
    long timeoutInMs = 60000; //The maximum amount of time we are willing to wait to set a connection.
    
    Map<InetSocketAddress, Channel> map = commSetup.prepareForCommunication(listOfParties, naive, timeoutInMs);
    
    // prepareForCommunication() returns a map with all the established channels,
    // we return only the first one since this code assumes the two-party case.
    return map.values().iterator().next();

.. _`connecting success`: 

Verifying that the connections were established
-----------------------------------------------

Different Multi-parties computations may require different types of success when checking the connections between all the parties that were supposed to participate. Some protocols may need to make sure that absolutely all parties participating in it have established connections one with another; other protocols may need only a certain percentage of connections to have succeeded. There are many possibilities and each one of them is represented by a class implementing the ``ConnectivitySuccessVerifier`` interface. The different classes that implement this interface will run different algorithms to verify the level of success of the connections. It is up to the user of the ``CommunicationSetup`` class to choose the relevant level and pass it on to the ``CommunicationSetup`` upon calling the ``prepareForCommuncation`` function.

.. java:type:: public interface ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

.. java:method:: public boolean hasSucceded(EstablishedConnections estCon, List<Party> originalListOfParties)
   :outertype: ConnectivitySuccessVerifier

   This function gets the information about the established connections as input and the original list of parties, then it runs a certain algorithm (determined by the implementing class), and it returns true or false according to the level of connectivity checked by the implementing algorithm.

   :param estCon: the actual established connections
   :param originalListOfParties: the original list of parties to connect to
   :return: ``true`` if the level of connectivity was reached (depends on implementing algorithm) and ``false`` otherwise.
   
Naive
~~~~~

.. java:type:: public class NaiveSuccess implements ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

   
NaiveSuccess does not actually check the connections but rather always returns true. It can be used when there is no need to verify any level of success in establishing the connections.

Clique
~~~~~~

.. java:type:: public class CliqueSuccess implements ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

   **For future implementation.**
   
   * Check if connected to all parties in original list.
   * Ask every party if they are connected to all parties in their list.
   * If all answers are true, return true,
   * Else, return false.

SecureClique
~~~~~~~~~~~~

.. java:type:: public class SecureCliqueSuccess implements ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

   **For future implementation.**
   
   * Check if connected to all parties in original list.
   * Ask every party if they are connected to all parties in their list. USE SECURE BROADCAST. DO NOT TRUST THE OTHER PARTIES.
   * If all answers are true, return true,
   * Else, return false.

TwoParties
~~~~~~~~~~

.. java:type:: public class TwoPartiesSuccess implements ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

   **For future implementation.**

Using an established connection
-------------------------------

A connection is represented by the :java:ref:`Channel` interface. Once a channel is established, we can ``send()`` and ``receive()`` data between parties.

.. java:type:: public interface Channel
   :package: edu.biu.scapi.comm

.. java:method:: public void send(Serializable data) throws IOException
   :outertype: Channel

   Sends a message *msg* to the other party, *msg* must be a ``Serializable`` object.

.. java:method:: public Serializable receive() throws ClassNotFoundException, IOException
   :outertype: Channel

   Receives a message from the channel. 

   :return: Returns the received message as ``Serializable``. Conversion to the right type is the responsiblity of the caller.

.. java:method:: public void close()
   :outertype: Channel

   Closes the connection.

.. java:method:: public boolean isClosed()
   :outertype: Channel

   :return: ``true`` if the connection is closed, ``false`` otherwise.

Security of the connection
--------------------------

A channel can have Plain, Encrypted or Authenticated security level, depending on the requirements of the application. The type of security set by the :java:ref:`CommunicationSetup` class is *Plain* security, and is represented by the class :java:ref:`PlainTCPChannel`. In case a higher security standard is needed, the user must set it manually, by using the decorator classes :java:ref:`AuthenticatedChannel` and :java:ref:`EncryptedChannel`.

PlainTcpChannel
~~~~~~~~~~~~~~~

Plain security is the default type of security set by the :java:ref:`CommunicationSetup`. You should never directly use the :java:ref:`PlainChannel` or :java:ref:`PlainTcpChannel` classes, as this type of security is set by default.

.. java:type:: public abstract class PlainChannel implements Channel
   :package: edu.biu.scapi.comm

.. java:type:: public class PlainTCPChannel extends PlainChannel
   :package: edu.biu.scapi.comm

   This type of channel ensures TCP type of communication.

AuthenticatedChannel
~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class AuthenticatedChannel extends ChannelDecorator

   This channel ensures :java:ref:`UnlimitedTimes` security level. The owner of the channel is responsible for setting the MAC algorithm to use and make sure the the MAC is initialized with a suitable key. Then, every message sent via this channel is authenticated using the underlying MAC algorithm and every message received is verified by it.

   The user needs not to worry about any of the authentication and verification tasks. The owner of this channel can rest assure that when an object gets sent over this channel it gets authenticated with the defined MAC algorithm. In the same way, when receiving a message sent over this channel (which was authenticated by the other party) the owner of the channel receives an already verified and plain object.

.. java:constructor:: public AuthenticatedChannel(Channel channel, Mac mac) throws SecurityLevelException
   :outertype: AuthenticatedChannel

   This public constructor can be used by anyone holding a channel that is connected. Such a channel can be obtained by running the prepareForCommunication function of :java:ref:`CommunicationSetup` which returns a set of already connected channels.

   :param channel: an already connected channel
   :param mac: the MAC algorithm required to authenticate the messages sent by this channel
   :throws SecurityLevelException: if the MAC algorithm passed is not UnlimitedTimes-secure

.. java:method:: public void setKey(SecretKey key) throws InvalidKeyException
   :outertype: AuthenticatedChannel

   Sets the key of the underlying MAC algorithm. This function must be called before sending or receiving messages if the MAC algorithm passed to this channel had not been set with a key yet. The key can be set indefinite number of times depending on the needs of the application.

   :param key: a suitable SecretKey
   :throws InvalidKeyException: if the given key does not match the underlying MAC algorithm.

Example of Usage:
^^^^^^^^^^^^^^^^^

We assume in this example that ``ch`` is an already established channel. We showed in previous examples how to setup a channel using CommunicationSetup. We stress that this the code for one party, but both parties must decorate their respective channels with :java:ref:`AuthenticatedChannel` for it to work.

.. code-block:: java

    import java.security.InvalidKeyException;
    
    import javax.crypto.SecretKey;
    import javax.crypto.spec.SecretKeySpec;
    
    import edu.biu.scapi.comm.*;
    import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
    import edu.biu.scapi.tools.Factories.*;
    import edu.biu.scapi.exceptions.*;
    
    public AuthenticatedChannel createAuthenticatedChannel(Channel ch) {
        Mac mac = null;
        try {
	    mac = MacFactory.getInstance().getObject("CBCMacPrepending(TripleDES)");
        } catch (FactoriesException e) {
	    e.printStackTrace();
        }
        //You could generate the key here and then somehow send it to the other party so the other party uses the same secret key
        //SecretKey keyMac = mac.generateKey(168);
        
        //Instead, we use a secretKey that has already been agreed upon by both parties:
        byte[] fixedKey = new byte[]{-77, -80, -111, 38, -33, -29, 31, 16, 87, -57, -42, 49, 87, 93, 73, 16, 76, 55, -111, 76, 103, -125, 25, -15};
        SecretKey key = new SecretKeySpec(fixedKey, "TripleDES");
        try {
	    mac.setKey(key);
        } catch (InvalidKeyException e) {
	    e.printStackTrace();
        }
        
        //Decorate the Plain TCP Channel with the authentication
        AuthenticatedChannel authenChannel = null;
        try {
	    authenChannel = new AuthenticatedChannel(ch, mac);
        } catch (SecurityLevelException e) {
	    // This exception will not happen since we chose a Mac that meets the Security Level requirements
	    e.printStackTrace();
        }
        
        return authenChannel;
    }

After converting the channel to an authenticated channel, we can simply call ``send()`` and ``receive()`` again in the same manner as before, only this time the messages are authenticated for us.

EncryptedChannel
~~~~~~~~~~~~~~~~

.. java:type:: public class EncryptedChannel extends ChannelDecorator

   This channel ensures :java:ref:`CPA` security level. The owner of the channel is responsible for setting the encryption scheme to use and make sure the the encryption scheme is initialized with a suitable key. Then, every message sent via this channel is encrypted and decrypted using the underlying encryption scheme.

   The user needs not to worry about any of the encryption or decryption tasks. The owner of this channel can rest assure that when an object gets sent over this channel it gets encrypted with the defined encryption scheme. In the same way, when receiving a message sent over this channel (which was encrypted by the other party) the owner of the channel receives an already decrypted object.

.. java:constructor:: public EncryptedChannel(Channel channel, SymmetricEnc encScheme) throws SecurityLevelException
   :outertype: EncryptedChannel

   This public constructor can be used by anyone holding a channel that is connected. Such a channel can be obtained by running the prepareForCommunications function of :java:ref:`CommunicationSetup` which returns a set of already connected channels.

   Creates a new EncryptedChannel that wraps the already connected channel mentioned above. The encryption scheme must be CPA-secure, otherwise an exception is thrown. The encryption scheme does not need to be initialized with a key at this moment (even though it can), but before sending or receiving a message over this channel the relevant secret key must be set with `setKey()`_.

   :param channel: an already connected channel
   :param encScheme: a symmetric encryption scheme that is CPA-secure.
   :throws SecurityLevelException: if the encryption scheme is not CPA-secure

.. _`setKey()`:

.. java:method:: public void setKey(SecretKey key) throws InvalidKeyException
   :outertype: EncryptedChannel

   Sets the key of the underlying encryption scheme. This function must be called before sending or receiving messages if the encryption scheme passed to this channel had not been set with a key yet. The key can be set indefinite number of times depending on the needs of the application.

   :param key: a suitable SecretKey
   :throws InvalidKeyException: if the given key does not match the underlying MAC algorithm.

Example of Usage
^^^^^^^^^^^^^^^^

This example is very similar to the previous one. As before we only show how to decorate the established channel after :java:ref:`CommunicationSetup` is called.

.. code-block:: java

    import java.io.IOException;
    import java.security.InvalidKeyException;
    
    import javax.crypto.SecretKey;
    import javax.crypto.spec.SecretKeySpec;
    
    import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.comm.EncryptedChannel;
    import edu.biu.scapi.exceptions.SecurityLevelException;
    import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScCTREncRandomIV;
    import edu.biu.scapi.primitives.prf.AES;
    import edu.biu.scapi.primitives.prf.bc.BcAES;
    
    public EncryptedChannel createEncryptedChannel(Channel ch) {
        ScCTREncRandomIV enc = null;
        try {
	    // first we generate the secret key for the PRP that is used by the encryption object.
    			
	    // You could generate the key here and then somehow send it to the other party so the other party uses the same secret key
	    // SecretKey encKey = SecretKeyGeneratorUtil.generateKey("AES");
	    //Instead, we use a secretKey that has already been agreed upon by both parties:
	    byte[] aesFixedKey = new byte[]{-61, -19, 106, -97, 106, 40, 52, -64, -115, -19, -87, -67, 98, 102, 16, 21};
	    SecretKey encKey = new SecretKeySpec(aesFixedKey, "AES");
	    
	    // now, we initialize the PRP, set the key, and then initialize the encryption object
	    AES aes = new BcAES();	
	    aes.setKey(encKey);
	    enc = new ScCTREncRandomIV(aes);
	    
        } catch (InvalidKeyException e) {
	    e.printStackTrace();
        }
        
        //Decorate the Plain TCP Channel with the EncryptedChannel class
        EncryptedChannel encChannel = null;
        try {
	    encChannel = new EncryptedChannel(ch, enc);
        } catch (SecurityLevelException e) {
	    // This exception will not happen since we chose an encryption scheme that meets the Security Level requirements
	    e.printStackTrace();
        }
        
        return encChannel;
    }

Encrypted and Authenticated Channel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We now provide an example of both encrypted and authenticated communication. This example is very similar to the previous one.

.. code-block:: java

    import java.io.IOException;
    import java.security.InvalidKeyException;
    
    import javax.crypto.SecretKey;
    import javax.crypto.spec.SecretKeySpec;
    
    import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.comm.EncryptedChannel;
    import edu.biu.scapi.exceptions.SecurityLevelException;
    import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScCTREncRandomIV;
    import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScEncryptThenMac;
    import edu.biu.scapi.midLayer.symmetricCrypto.mac.ScCbcMacPrepending;
    import edu.biu.scapi.primitives.prf.AES;
    import edu.biu.scapi.primitives.prf.TripleDES;
    import edu.biu.scapi.primitives.prf.bc.BcAES;
    import edu.biu.scapi.primitives.prf.bc.BcTripleDES;
    
    public EncryptedChannel createSecureChannel(Channel ch) {
        ScCTREncRandomIV enc = null;
        ScCbcMacPrepending cbcMac = null;
        try {
	    // first, we set the encryption object
        	
	    // You could generate the key here and then somehow send it to the other party so the other party uses the same secret key
	    // SecretKey encKey = SecretKeyGeneratorUtil.generateKey("AES");
	    //Instead, we use a secretKey that has already been agreed upon by both parties:
	    byte[] aesFixedKey = new byte[]{-61, -19, 106, -97, 106, 40, 52, -64, -115, -19, -87, -67, 98, 102, 16, 21};
	    SecretKey encKey = new SecretKeySpec(aesFixedKey, "AES");
	    
	    AES aes = new BcAES();
	    aes.setKey(encKey);
	    
	    // create encryption object from PRP
	    enc = new ScCTREncRandomIV(aes);
	    
	    // second, we create the mac object
	    TripleDES tripleDes = new BcTripleDES();		
	    
	    //You could generate the key here and then somehow send it to the other party so the other party uses the same secret key
	    //SecretKey macKey = SecretKeyGeneratorUtil.generateKey("TripleDES");
	    //Instead, we use a secretKey that has already been agreed upon by both parties:
	    byte[] fixedKey = new byte[]{32, 19, -105, 107, 26, 13, 26, -43, -36, 38, -20, 93, -39, 94, 16, -88, 19, 69, 67, 103, 93, 37, -122, -88};
	    SecretKey macKey = new SecretKeySpec(fixedKey,"TripleDES");
	    tripleDes.setKey(macKey);
	    // create Mac object from PRP
	    cbcMac = new ScCbcMacPrepending(tripleDes);
	    
        } catch (InvalidKeyException e) {
	    e.printStackTrace();
        }
        
        //Create the encrypt-then-mac object using encryption and authentication objects. 
        ScEncryptThenMac encThenMac = null;
        encThenMac = new ScEncryptThenMac(enc, cbcMac);
        
        //Decorate the Plain TCP Channel with the authentication
        EncryptedChannel secureChannel = null;
        try {
	    secureChannel = new EncryptedChannel(ch, encThenMac);
	} catch (SecurityLevelException e) {
	    // This exception will not happen since we chose a Mac that meets the Security Level requirements
	    e.printStackTrace();
	}
	
	return secureChannel;
    }
