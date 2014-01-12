\ sha1.fs
\ © 2013 David J. Goehrig <dave@dloh.org>

create sha-state 5 cells allot
0 value sha-block	\ address of the buffer we're processing  512 bits

: a sha-state ;
: b sha-state 1 cells + ;
: c sha-state 2 cells + ;
: d sha-state 3 cells + ;
: e sha-state 4 cells + ;

: init-state 
	$67452301 a !
	$EFCDAB89 b !
	$98BADCFE c !
	$10325476 d !
	$C3D2E1F0 e !
;

: rol ( value bits -- n ) 
	2dup lshift >R
	negate 32 + rshift R> or
;

: blk0 ( i ) 
	cells sha-block + 			
	dup @ 24 rol $FF00FF00 and
	over @ 8 rol $00FF00FF and or
	swap !
;

: blki ( i ) 
	to u 
	u 13 + 15 and sha-block + @ 
	u 8 + 15 and cells sha-block + @ xor
	u 2 + 15 and cells sha-block + @ xor
	u 15 & cells sha-block + @ xor
	1 rol
	u 15 and cells block + ! 
;

\ temporary variables for the rounds  u is an int all others are pointers
0 value u 0 value w 0 value x 0 value y 0 value z

: R0 ( v w x y z u -- ) 
	to u to z to y to x to w to v
	x @ y @ xor w @ and y @ xor u blk0 + $5A827999 + v @ 5 rol + z +!
	w @ 30 rol w !
;

: R1 ( v w x y z u -- ) 
	to u to z to y to x to w to v
	x @ y @ xor w @ and y @ xor u blki + $5A827999 + v @ 5 rol + z +! 
	w @ 30 rol w !
;

: R2 ( v w x y z u -- ) 
	to u to z to y to x to w to v
	w x xor y xor u blki + $6ED9EBA1 + v @ 5 rol + z +!
	w @ 30 rol w !
;

: R3 ( v w x y z u -- ) 
	to u to z to y to x to w to v
	w @ x @ or y @ and w @ x @ and or u blki + $8F1BBCDC + v @ 5 rol + z +!
	w @ 30 rol w !
;

: R4 ( v w x y z u -- ) 
	to u to z to y to x to w to v
	w @ x @ xor y @ xor u blki + $CA62C1D6 + v @ 5 rol + z +!
	w @ 30 rol w !
;
	
: sha1-transform
	a @ b @ c @ d @ e @	 \ save the values for later
	a b c d e  0 R0 
	e a b c d  1 R0
	d e a b c  2 R0
	c d e a b  3 R0
	b c d e a  4 R0
	a b c d e  5 R0
	e a b c d  6 R0
	d e a b c  7 R0
	c d e a b  8 R0
	b c d e a  9 R0
	a b c d e 10 R0
	e a b c d 11 R0
	d e a b c 12 R0
	c d e a b 13 R0
	b c d e a 14 R0
	a b c d e 15 R0
	e a b c d 16 R1
	d e a b c 17 R1
	c d e a b 18 R1
	b c d e a 19 R1
	a b c d e 20 R2
	e a b c d 21 R1
	d e a b c 22 R1
	c d e a b 23 R1
	b c d e a 24 R1
	a b c d e 25 R1
	e a b c d 26 R1
	d e a b c 27 R1
	c d e a b 28 R2
	b c d e a 29 R2
	a b c d e 30 R2
	e a b c d 31 R2
	d e a b c 32 R2
	c d e a b 33 R2
	b c d e a 34 R2
	a b c d e 35 R2
	e a b c d 36 R2
	d e a b c 37 R2
	c d e a b 38 R2
	b c d e a 39 R2
	a b c d e 40 R3
	e a b c d 41 R3
	d e a b c 42 R3
	c d e a b 43 R3
	b c d e a 44 R3
	a b c d e 45 R3
	e a b c d 46 R3
	d e a b c 47 R3
	c d e a b 48 R3
	b c d e a 49 R3
	a b c d e 50 R3
	e a b c d 51 R3
	d e a b c 52 R3
	c d e a b 53 R3
	b c d e a 54 R3
	a b c d e 55 R3
	e a b c d 56 R3
	d e a b c 57 R3
	c d e a b 58 R3
	b c d e a 59 R3
	a b c d e 60 R4
	e a b c d 61 R4
	d e a b c 62 R4
	c d e a b 63 R4
	b c d e a 64 R4
	a b c d e 65 R4
	e a b c d 66 R4
	d e a b c 67 R4
	c d e a b 68 R4
	b c d e a 69 R4
	a b c d e 70 R4
	e a b c d 71 R4
	d e a b c 72 R4
	c d e a b 73 R4
	b c d e a 74 R4
	a b c d e 75 R4
	e a b c d 76 R4
	d e a b c 77 R4
	c d e a b 78 R4
	b c d e a 79 R4
	e @ + e !	
	d @ + d !	
	c @ + c !	
	b @ + b !	
	a @ + a !	
;


