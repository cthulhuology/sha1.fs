sha1.fs
-----------

A Portable SHA1 implementation in Forth


Getting Started
---------------

This code currenly only support messages of < 56 characters.  I need to do
some additional work to add additional rounds of 512 bit bocks.

To add to your gforth project

	s" sha1.fs" included
	s" abc" sha1 digest

Which will print out the sha1 digest.  The values of the 160 bit digest are
in the sha-digest buffer.


About
-----

This implementation is based on 

http://www.itl.nist.gov/fipspubs/fip180-1.htm

and is a straight forward implementation based on the mainline algo.

Little effort has been put into optimizing the forth, and even less for speed.

Complaints & Bug Fixed
----------------------

Please send any complaints or patches to:

	David Goehrig <dave@dloh.org>
