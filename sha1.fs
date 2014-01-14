
\ pad out the message so that the message is a multiple of 512 bits (64 bytes)

create sha-block 64 allot
sha-block 64 0 fill

create sha-schedule 80 cells allot	\ NB: these are 64 bits but we only use 32
sha-schedule 80 cells 0 fill

: tobig32
	>R 
	R@ $ff and 24 lshift
	R@ $ff00 and 8 lshift
	R@ $ff0000 and 8 rshift
	R@ $ff000000 and 24 rshift
	or or or
	R> drop
;

: tobig64
	>R
	R@ $ff and 56 lshift
	R@ $ff00 and 40 lshift
	R@ $ff0000 and 24 lshift
	R@ $ff000000 and 8 lshift
	R@ $ff00000000 and 8 rshift
	R@ $ff0000000000 and 24 rshift
	R@ $ff000000000000 and 40 rshift
	R@ $ff00000000000000 and 56 rshift
	or or or or or or or
	R> drop
;

: sha-block-clear sha-block 64 0 fill ;

: sha-block-dump sha-block 64 dump ;

0 value len
: sha-pad ( n < 56 -- )
	to len
	len 63 and 56 swap - 0 do
		i 0= if $80 else 0 then
		len i + sha-block + c!
	loop 
	len 3 lshift tobig64 sha-block 56 + !		\ len is in bits
;

: sha-string >R sha-block R@ cmove R> sha-pad ;	\ works assuming string is less than 56 characters

create sha-digest 5 cells allot
: h0 sha-digest ;
: h1 sha-digest 1 cells + ;
: h2 sha-digest 2 cells + ;
: h3 sha-digest 3 cells + ;
: h4 sha-digest 4 cells + ;

: sha-digest-init
	$67452301 h0 !
	$EFCDAB89 h1 !
	$98BADCFE h2 !
	$10325476 h3 !
	$C3D2E1F0 h4 !
;
\ immediately invoke to update so our later values are preseeded correctly
sha-digest-init

$5A827999 constant k0r \ 0 - 19
$6ED9EBA1 constant k1r \ 20 - 39
$8F1BBCDC constant k2r \ 40 - 59
$CA62C1D6 constant k3r \ 60 - 79

0 value X
0 value Y
0 value Z

: f0 ( B C D -- n )  ( 0 <= t <= 19 ) 
	to Z to Y to X
	X Y and X invert Z and OR ;

: f1 ( B C D -- n ) ( 20 <= t <= 39) 
	to Z to Y to X
 	X Y XOR Z XOR ;

: f2 ( B C D -- n ) ( 40 <= t <= 59) 
	to Z to Y to X
 	X Y AND X Z AND OR Y Z AND OR ;

: f3 ( B C D -- n ) ( 60 <= t <= 79)
	to Z to Y to X
	X Y XOR Z XOR ;

: w0 sha-block ;
: w1 sha-block 4 + ;
: w2 sha-block 8 + ;
: w3 sha-block 12 + ;
: w4 sha-block 16 + ;
: w5 sha-block 20 + ;
: w6 sha-block 24 + ;
: w7 sha-block 28 + ;
: w8 sha-block 32 + ;
: w9 sha-block 36 + ;
: w10 sha-block 40 + ;
: w11 sha-block 44 + ;
: w12 sha-block 48 + ;
: w13 sha-block 52 + ;
: w14 sha-block 56 + ;
: w15 sha-block 60 + ;

\ does a 32 bit rotate 
: bitrot ( x n )	
	2dup lshift $ffffffff and >R
	negate 32 + rshift $ffffffff and R> or ;

: !w cells sha-schedule + ! ;
: @w cells sha-schedule + @ tobig32 ;

\ load the padded buffer into the schedule array
: load-schedule
	w0 l@ 0 !w
	w1 l@ 1 !w
	w2 l@ 2 !w
	w3 l@ 3 !w
	w4 l@ 4 !w
	w5 l@ 5 !w
	w6 l@ 6 !w
	w7 l@ 7 !w
	w8 l@ 8 !w
	w9 l@ 9 !w
	w10 l@ 10 !w
	w11 l@ 11 !w
	w12 l@ 12 !w
	w13 l@ 13 !w
	w14 l@ 14 !w
	w15 l@ 15 !w
;

: expand-schedule 80 16 do  I 3 - @w I 8 - @w xor I 14 - @w xor I 16 - @w xor 1 bitrot tobig32 I !w loop ;

\ temporary values
h0 @ value a
h1 @ value b
h2 @ value c
h3 @ value d
h4 @ value e
0 value temp

: fn  
	dup 20 < if drop f0 else
	dup 40 < if drop f1 else
	dup 60 < if drop f2 else
		drop f3 then then then ;

: kn
	dup 20 < if drop k0r else
	dup 40 < if drop k1r else
	dup 60 < if drop k2r else
		drop k3r then then then ;

: sha-hash
	h0 @ to a
	h1 @ to b
	h2 @ to c
	h3 @ to d
	h4 @ to e
	load-schedule
	expand-schedule
	\ cr hex a .  b . c . d . e . decimal cr
	80 0 do
		\ TEMP = S5(A) + ft(B,C,D) + E + Wt + Kt; 
		a 5 bitrot b c d I fn + e + I @w + I kn +  $ffffffff and to temp
 	
		\ E = D; D = C; C = S30(B); B = A; A = TEMP; 
		d to e c to d b 30 bitrot to c a to b temp to a
		\ hex I . a .  b . c . d . e . decimal cr
	loop
	h0 @ a + h0 !
	h1 @ b + h1 !
	h2 @ c + h2 !
	h3 @ d + h3 !
	h4 @ e + h4 !
;

: sha1 ( a n -- ) sha-string sha-digest-init sha-hash ;

: digest hex 
	sha-digest l@ . 
	sha-digest 1 cells + l@ .
	sha-digest 2 cells + l@ .
	sha-digest 3 cells + l@ .
	sha-digest 4 cells + l@ .
	decimal ;

: test-sha1 s" abc" sha1 digest ." == A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D " cr ;
