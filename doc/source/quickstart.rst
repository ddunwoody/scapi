Quickstart
==========

Eager to get started? This page gives a good introduction to SCAPI. It assumes you already have SCAPI installed. If you do not, head over to the :ref:`Installation <install>` section.


Your First Scapi Application
----------------------------

We begin with a minimal application and go through some basic examples.

.. sourcecode:: java
    :emphasize-lines: 16
    
    import java.io.IOException;
    import java.math.BigInteger;
    import java.security.SecureRandom;

    import org.bouncycastle.util.BigIntegers;

    import edu.biu.scapi.primitives.dlog.DlogGroup;
    import edu.biu.scapi.primitives.dlog.GroupElement;
    import edu.biu.scapi.primitives.dlog.openSSL.OpenSSLDlogECF2m;

    public class DlogExample {

        public static void main(String[] args) throws IOException {
            // initiate a discrete log group
	    // (in this case the OpenSSL implementation of the elliptic curve group K-233)
	    DlogGroup dlog = new OpenSSLDlogECF2m("K-233");
	    SecureRandom random = new SecureRandom();
		
	    // get the group generator and order 
	    GroupElement g = dlog.getGenerator();
	    BigInteger q = dlog.getOrder();
	    BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		
	    // create a random exponent r
	    BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
	    // exponentiate g in r to receive a new group element
	    GroupElement g1 = dlog.exponentiate(g, r);
	    // create a random group element
	    GroupElement h = dlog.createRandomElement();
	    // multiply elements
	    GroupElement gMult = dlog.multiplyGroupElements(g1, h);
	}
    }

Pay attention to the definition of the discrete log group. In Scapi we will always use a generic data type
such as ``DlogGroup`` instead of a more specified data type. This allows us to replace the group to a
different implementation or a different group entirely, without changing our code.

Let's break it down:
~~~~~~~~~~~~~~~~~~~~

We first imported the needed classes that are built-in in java. Scapi uses heavily the ``SecureRandom`` class. This class provides a cryptographically strong random number generator (RNG). We also use the ``BigInteger`` type to handle big numbers. Since java has such class we do not need to re-implement it in Scapi.

.. sourcecode:: java
    
    import java.math.BigInteger;
    import java.security.SecureRandom;

We import the BouncyCastle utility class ``BigIntegers`` that provide a very convenient function to generate a random big integer in a given range.

.. sourcecode:: java

    import org.bouncycastle.util.BigIntegers;

We import the Scapi generic primitives ``DlogGroup`` (implements a discrete log group) and ``GroupElement`` (a group member). We then import the ``OpenSSLDlogECF2m`` class. This is a wrapper class to a native implementation of an elliptic curve group in the OpenSSL library. Since ``GroupElement`` and ``DlogGroup`` are interfaces, we can easily choose a different group without changing a single line of code except the one in emphasis.

.. sourcecode:: java

    import edu.biu.scapi.primitives.dlog.DlogGroup;
    import edu.biu.scapi.primitives.dlog.GroupElement;
    import edu.biu.scapi.primitives.dlog.openSSL.OpenSSLDlogECF2m;

Our main class defines a discrete log group, and then extract the group properties (generator and order).

.. sourcecode:: java

    public class DlogExample {

        public static void main(String[] args) throws IOException {
            // initiate a discrete log group
	    // (in this case the OpenSSL implementation of the elliptic curve group K-233)
	    DlogGroup dlog = new OpenSSLDlogECF2m("K-233");
	    SecureRandom random = new SecureRandom();
		
	    // get the group generator and order 
	    GroupElement g = dlog.getGenerator();
	    BigInteger q = dlog.getOrder();
	    BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		
	    ...
	}
    }

We then choose a random exponent, and exponentiate the generator in this exponent.

.. sourcecode:: java

    // create a random exponent r
    BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
    // exponentiate g in r to receive a new group element
    GroupElement g1 = dlog.exponentiate(g, r);

We then select another group element randomly.

.. sourcecode:: java

    // create a random group element
    GroupElement h = dlog.createRandomElement();

Finally, we demonstrate how to multiply group elements.

.. sourcecode:: java

    // multiply elements
    GroupElement gMult = dlog.multiplyGroupElements(g1, h);

Compiling and Running the Scapi Code
------------------------------------

Save this example to a file called *DlogExample.java*. In order to compile this file, type in the terminal: ::

    $ scapic DlogExample.java

The ``scapic`` command is created during the installation of scapi, and is used instead of the ``javac`` command.
In reality, ``scapic`` is actually a shortcut to ``javac`` with the Scapi jar files appended to the java *classpath*.

A file called *DlogExample.class* should be created as a result. In order to run this file, type in the terminal: ::

    $ scapi DlogExample

Like ``scapic``, ``scapi`` replaces the ``java`` command, and defines the java classpath correctly as well as import 
the scapi jni interface shared libraries.

Establishing Secure Communication
---------------------------------

The first thing that needs to be done to obtain communication services is to setup the connections between the different parties. Each party needs to run the setup process at the end of which the established connections are obtained. The established connections are called *channels*.

The ``CommunicationSetup`` Class is responsible for establishing secure communication to other parties. An application requesting from ``CommunicationSetup`` to prepare for communication needs to call the ``CommunicationSetup::prepareForCommunication()`` function:

.. java:method:: Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties, ConnectivitySuccessVerifier successLevel, long timeOut, boolean enableNagle)

    :param List<Party> listOfParties: The list of parties to connect to. As a convention, we will set the first party in the list to be the requesting party, that is, the party represented by the application.
    :param ConnectivitySuccessVerifier successLevel: The type of connecting success required.
    :param long timeOut: A time-out (in milliseconds) specifying how long to wait for connections to be established and secured.
    :param boolean enableNagle: Whether or not `Nagle’s algorithm <http://en.wikipedia.org/wiki/Nagle's_algorithm>` can be enabled.
    :return: a map of the established channels.

Let's add the following method to the ``DlogExample`` class:

.. code-block:: java
    :emphasize-lines: 27

    import java.net.InetSocketAddress;
    import java.util.List;
    import java.util.Map;

    import edu.biu.scapi.comm.Party;
    import edu.biu.scapi.comm.LoadParties;

    import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.comm.CommunicationSetup;

    import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
    import edu.biu.scapi.comm.NaiveSuccess;

    private static Channel setCommunication() {
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
    }

In this example, the list of parties is read from a properties file called *Parties0.properties*: ::

    # A configuration file for the parties

    NumOfParties = 2

    IP0 = 127.0.0.1
    IP1 = 127.0.0.1

    Port0 = 8001
    Port1 = 8000

A ``Channel`` represents an established connection between two parties. A channel can have Plain, Encrypted or Authenticated security level, depending on the requirements of the application. In all cases the channel has two main functions:

.. java:method:: public void send(Serializable data) throws IOException

   Sends a message *msg* to the other party, *msg* must be a ``Serializable`` object.

.. java:method:: public Serializable receive() throws ClassNotFoundException, IOException

   Receives a message from the channel. Conversion to the right type is the responsiblity of the caller.

This means that from the applications point of view, once it obtains the channels and sets their Security Level it can completely forget about it and just send and receive messages knowing that all the encryption or authentication work is done automatically.

..
   How to set an Encrypted Channel manually
   ----------------------------------------

   Some text.

   Using Public Key Encryption
   ---------------------------

   Some text.

   Using 1-out-of-2 Oblivious Trasfer
   ----------------------------------

   Some text.

   Using Commitment Schemes
   ------------------------

   Some text.

   Using Sigma Protocols
   ---------------------

   Some text.

   Using Zero Knowledge Proofs
   ---------------------------

   Some text.
