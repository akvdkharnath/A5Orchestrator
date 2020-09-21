A5Orchestrator
======

A simple python wrapper for Orchestrator API.
Use it to control Orchestrator in UI Path.

The code is Python 3, but Python 2 compatible.

Installation
------------

Fast install:

::

    pip install 

For a manual install get this package:

::

    wget https://github.com/nikhilkumarsingh/mygmap/archive/master.zip
    unzip master.zip
    rm master.zip
    cd mygmap-master

Install the package:

::

    python setup.py install    

Example
--------

.. code:: python

    from geo import locator

    # get formatted address of any location
    print locator.get_address("rohini, delhi")

    # get co-ordinates of location
    print locator.get_coordinates("delhi")

    

Here is the output:

Rohini, New Delhi, Delhi, India
(28.7040592, 77.10249019999999)
