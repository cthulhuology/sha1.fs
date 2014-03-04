include sha1.fs

: test1-str s" abc" ;
: test2-str s" abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" ;
: test3-str s" a" ;
: test4-str s" abc" ;
: test5-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabc" ;
: test6-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd" ;
: test7-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde" ;
: test8-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij" ;
: test9-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk" ;
: test10-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl" ;
: test11-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm" ;
: test12-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl" ;
: test13-str s" abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcdefg" ;


: test1-hash ." a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d" ;
: test2-hash ." 84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1" ;
: test3-hash ." 86f7e437 faa5a7fc e15d1ddc b9eaeaea 377667b8" ;
: test4-hash ." a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d" ;
: test5-hash ." a617d006 d1ca1267 1785098a 19a87fe5 8443bde9" ;
: test6-hash ." 4ad5bb7a e3c40247 68d364b7 7c52128e a3cffebe" ;
: test7-hash ." e1b3b34d a0f7b299 090824d9 aa81fff6 711a79ad" ;
: test8-hash ." 3ba53d6c b1408a0c b3552042 8a5916ae fca1500e" ;
: test9-hash ." fc8a5ab7 72596250 85ead3ec 96515b3b 8d933fad" ;
: test10-hash ." 93249d4c 2f8903eb f41ac358 473148ae 6ddd7042" ;
: test11-hash ." cf2a63cc 308225cf 07b498d2 309a01dd 0df52f67" ;
: test12-hash ." 62e2d1a6 1720b0cd 63b531aa 59edc89d 4276cf98" ;
: test13-hash ." a38fde77 e4e8d512 bdf271be cfbaef6a 7fac2936" ;

: test1 test1-str sha1 digest ."  = " test1-hash cr ;
: test2 test2-str sha1 digest ."  = " test2-hash cr ;
: test3 test3-str sha1 digest ."  = " test3-hash cr ;
: test4 test4-str sha1 digest ."  = " test4-hash cr ;
: test5 test5-str sha1 digest ."  = " test5-hash cr ;
: test6 test6-str sha1 digest ."  = " test6-hash cr ;
: test7 test7-str sha1 digest ."  = " test7-hash cr ;
: test8 test8-str sha1 digest ."  = " test8-hash cr ;
: test9 test9-str sha1 digest ."  = " test9-hash cr ;
: test10 test10-str sha1 digest ."  = " test10-hash cr ;
: test11 test11-str sha1 digest ."  = " test11-hash cr ;
: test12 test12-str sha1 digest ."  = " test12-hash cr ;
: test13 test13-str sha1 digest ."  = " test13-hash cr ;


