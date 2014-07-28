.. _install:

Installation
============

Scapi is simple enough to install, the installation varies on different operating systems. Scapi currently supports Linux_, `Mac OS X`_, and Windows_.

.. _Linux:
.. _`Mac OS X`:

Prequisities
------------

There are a few prerequisites you must install before being able to compile scapi on your machine.

1.  Install `git`_
2.  Install `java`_ and `ant`_
3.  Install the `gcc`_ compiler environment: `gcc`, `make`, `ar`, `ld`, etc. Under Ubuntu you can simply run ``sudo apt-get install build-essential``.

Installing Scapi from Source (On UNIX-based Operating Systems)
--------------------------------------------------------------

In order to install scapi: ::

  $ git clone git://github.com/cryptobiu/scapi.git
  $ cd scapi
  $ git submodule init
  $ git submodule update
  $ make
  $ sudo make install

.. _Windows:

Instructions for Windows
------------------------

TBD.

.. _git: http://git-scm.org/
.. _java: http://java.com/
.. _ant: http://ant.apache.org/
.. _gcc: http://gcc.gnu.org/
