// nettle, low-level cryptographics library
// 
// Copyright (C) 2004, Niels Möller
//  
// The nettle library is free software; you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation; either version 2.1 of the License, or (at your
// option) any later version.
// 
// The nettle library is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
// License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with the nettle library; see the file COPYING.LIB.  If not, write to
// the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
// MA 02111-1307, USA.

// Register usage
#define SA	%eax
#define SB	%ebx
#define SC	%ecx
#define SD	%edx
#define SE	%ebp
#define DATA	%esp
#define TMP	%edi
#define TMP2	%esi			// Used by SWAP and F3
#define TMP3	64(%esp)

// Constants
#define K1VALUE	$0x5A827999		// Rounds  0-19
#define K2VALUE	$0x6ED9EBA1		// Rounds 20-39
#define K3VALUE	$0x8F1BBCDC		// Rounds 40-59
#define K4VALUE	$0xCA62C1D6		// Rounds 60-79

#define OFFSET(i) 4*(i)

// Reads the input via TMP2 into register, byteswaps it, and stores it in
// the DATA array.
#define SWAP(index, register)				\
	off=OFFSET(index);				\
	movl	off(TMP2), register;			\
	bswap	register;				\
	movl	register, off(DATA)

// expand(i) is the expansion function
//
//   W[i] = (W[i - 16] ^ W[i - 14] ^ W[i - 8] ^ W[i - 3]) <<< 1
//
// where W[i] is stored in DATA[i mod 16].
//
// Result is stored back in W[i], and also left in TMP, the only
// register that is used.
#define EXPAND(i)						\
	off=OFFSET(i % 16);	 	movl	off(DATA), TMP;	\
	off=OFFSET((i + 2) % 16);	xorl	off(DATA), TMP;	\
	off=OFFSET((i + 8) % 16);	xorl	off(DATA), TMP;	\
	off=OFFSET((i + 13) % 16);	xorl	off(DATA), TMP;	\
	roll	$1, TMP;					\
	off=OFFSET(i % 16);	 	movl	TMP, off(DATA)

// The f functions,
//
//  f1(x,y,z) = z ^ (x & (y ^ z))
//  f2(x,y,z) = x ^ y ^ z
//  f3(x,y,z) = (x & y) | (z & (x | y))
//  f4 = f2
//
// The macro Fk(x,y,z) computes = fk(x,y,z). 
// Result is left in TMP.
#define F1(x,y,z)						\
	movl	z, TMP;						\
	xorl	y, TMP;						\
	andl	x, TMP;						\
	xorl	z, TMP

#define F2(x,y,z)						\
	movl	x, TMP;						\
	xorl	y, TMP;						\
	xorl	z, TMP

#define F3(x,y,z)						\
	movl	x, TMP2;					\
	andl	y, TMP2;					\
	movl	x, TMP;						\
	orl	y, TMP;						\
	andl	z, TMP;						\
	orl	TMP2, TMP

// The form of one sha1 round is
//
//   a' = e + a <<< 5 + f( b, c, d ) + k + w;
//   b' = a;
//   c' = b <<< 30;
//   d' = c;
//   e' = d;
//
// where <<< denotes rotation. We permute our variables, so that we
// instead get
//
//   e += a <<< 5 + f( b, c, d ) + k + w;
//   b <<<= 30
//
// Using the TMP register for the roll can be avoided, by rotating
// %a in place, adding, and then rotating back.
#define ROUND(a,b,c,d,e,f,k,w)					\
	addl	k, e;						\
	addl	w, e;						\
	f(b,c,d);						\
	addl	TMP, e;						\
	movl	a, TMP;						\
	roll	$5, TMP;					\
	addl	TMP, e;						\
	roll	$30, b;

	// _nettle_sha1_compress(uint32_t *state, uint8_t *data)
	
.text
.align 16
.globl _nettle_sha1_compress
.type _nettle_sha1_compress,%function
_nettle_sha1_compress:
	// save all registers that need to be saved
	
	pushl	%ebx		//  80(%esp)
	pushl	%ebp		//  76(%esp)
	pushl	%esi		//  72(%esp)
	pushl	%edi		//  68(%esp)

	subl	$68, %esp	//  %esp = W

	// Load and byteswap data
	movl	92(%esp), TMP2

	SWAP( 0, %eax); SWAP( 1, %ebx); SWAP( 2, %ecx); SWAP( 3, %edx)
	SWAP( 4, %eax); SWAP( 5, %ebx); SWAP( 6, %ecx); SWAP( 7, %edx)
	SWAP( 8, %eax); SWAP( 9, %ebx); SWAP(10, %ecx); SWAP(11, %edx)
	SWAP(12, %eax); SWAP(13, %ebx); SWAP(14, %ecx); SWAP(15, %edx)

	// load the state vector
	movl	88(%esp),TMP
	movl	(TMP),   SA
	movl	4(TMP),  SB
	movl	8(TMP),  SC
	movl	12(TMP), SD
	movl	16(TMP), SE

	movl	K1VALUE, TMP2	
	off=OFFSET( 0); ROUND(SA, SB, SC, SD, SE, F1, TMP2, off(DATA))
	off=OFFSET( 1); ROUND(SE, SA, SB, SC, SD, F1, TMP2, off(DATA))
	off=OFFSET( 2); ROUND(SD, SE, SA, SB, SC, F1, TMP2, off(DATA))
	off=OFFSET( 3); ROUND(SC, SD, SE, SA, SB, F1, TMP2, off(DATA))
	off=OFFSET( 4); ROUND(SB, SC, SD, SE, SA, F1, TMP2, off(DATA))

	off=OFFSET( 5); ROUND(SA, SB, SC, SD, SE, F1, TMP2, off(DATA))
	off=OFFSET( 6); ROUND(SE, SA, SB, SC, SD, F1, TMP2, off(DATA))
	off=OFFSET( 7); ROUND(SD, SE, SA, SB, SC, F1, TMP2, off(DATA))
	off=OFFSET( 8); ROUND(SC, SD, SE, SA, SB, F1, TMP2, off(DATA))
	off=OFFSET( 9); ROUND(SB, SC, SD, SE, SA, F1, TMP2, off(DATA))

	off=OFFSET(10); ROUND(SA, SB, SC, SD, SE, F1, TMP2, off(DATA))
	off=OFFSET(11); ROUND(SE, SA, SB, SC, SD, F1, TMP2, off(DATA))
	off=OFFSET(12); ROUND(SD, SE, SA, SB, SC, F1, TMP2, off(DATA))
	off=OFFSET(13); ROUND(SC, SD, SE, SA, SB, F1, TMP2, off(DATA))
	off=OFFSET(14); ROUND(SB, SC, SD, SE, SA, F1, TMP2, off(DATA))

	off=OFFSET(15); ROUND(SA, SB, SC, SD, SE, F1, TMP2, off(DATA))
	EXPAND(16); ROUND(SE, SA, SB, SC, SD, F1, TMP2, TMP)
	EXPAND(17); ROUND(SD, SE, SA, SB, SC, F1, TMP2, TMP)
	EXPAND(18); ROUND(SC, SD, SE, SA, SB, F1, TMP2, TMP)
	EXPAND(19); ROUND(SB, SC, SD, SE, SA, F1, TMP2, TMP)

	// TMP2 is free to use in these rounds
	movl	K2VALUE, TMP2
	EXPAND(20); ROUND(SA, SB, SC, SD, SE, F2, TMP2, TMP)
	EXPAND(21); ROUND(SE, SA, SB, SC, SD, F2, TMP2, TMP)
	EXPAND(22); ROUND(SD, SE, SA, SB, SC, F2, TMP2, TMP)
	EXPAND(23); ROUND(SC, SD, SE, SA, SB, F2, TMP2, TMP)
	EXPAND(24); ROUND(SB, SC, SD, SE, SA, F2, TMP2, TMP)

	EXPAND(25); ROUND(SA, SB, SC, SD, SE, F2, TMP2, TMP)
	EXPAND(26); ROUND(SE, SA, SB, SC, SD, F2, TMP2, TMP)
	EXPAND(27); ROUND(SD, SE, SA, SB, SC, F2, TMP2, TMP)
	EXPAND(28); ROUND(SC, SD, SE, SA, SB, F2, TMP2, TMP)
	EXPAND(29); ROUND(SB, SC, SD, SE, SA, F2, TMP2, TMP)

	EXPAND(30); ROUND(SA, SB, SC, SD, SE, F2, TMP2, TMP)
	EXPAND(31); ROUND(SE, SA, SB, SC, SD, F2, TMP2, TMP)
	EXPAND(32); ROUND(SD, SE, SA, SB, SC, F2, TMP2, TMP)
	EXPAND(33); ROUND(SC, SD, SE, SA, SB, F2, TMP2, TMP)
	EXPAND(34); ROUND(SB, SC, SD, SE, SA, F2, TMP2, TMP)

	EXPAND(35); ROUND(SA, SB, SC, SD, SE, F2, TMP2, TMP)
	EXPAND(36); ROUND(SE, SA, SB, SC, SD, F2, TMP2, TMP)
	EXPAND(37); ROUND(SD, SE, SA, SB, SC, F2, TMP2, TMP)
	EXPAND(38); ROUND(SC, SD, SE, SA, SB, F2, TMP2, TMP)
	EXPAND(39); ROUND(SB, SC, SD, SE, SA, F2, TMP2, TMP)

	// We have to put this constant on the stack
	movl	K3VALUE, TMP3
	EXPAND(40); ROUND(SA, SB, SC, SD, SE, F3, TMP3, TMP)
	EXPAND(41); ROUND(SE, SA, SB, SC, SD, F3, TMP3, TMP)
	EXPAND(42); ROUND(SD, SE, SA, SB, SC, F3, TMP3, TMP)
	EXPAND(43); ROUND(SC, SD, SE, SA, SB, F3, TMP3, TMP)
	EXPAND(44); ROUND(SB, SC, SD, SE, SA, F3, TMP3, TMP)

	EXPAND(45); ROUND(SA, SB, SC, SD, SE, F3, TMP3, TMP)
	EXPAND(46); ROUND(SE, SA, SB, SC, SD, F3, TMP3, TMP)
	EXPAND(47); ROUND(SD, SE, SA, SB, SC, F3, TMP3, TMP)
	EXPAND(48); ROUND(SC, SD, SE, SA, SB, F3, TMP3, TMP)
	EXPAND(49); ROUND(SB, SC, SD, SE, SA, F3, TMP3, TMP)

	EXPAND(50); ROUND(SA, SB, SC, SD, SE, F3, TMP3, TMP)
	EXPAND(51); ROUND(SE, SA, SB, SC, SD, F3, TMP3, TMP)
	EXPAND(52); ROUND(SD, SE, SA, SB, SC, F3, TMP3, TMP)
	EXPAND(53); ROUND(SC, SD, SE, SA, SB, F3, TMP3, TMP)
	EXPAND(54); ROUND(SB, SC, SD, SE, SA, F3, TMP3, TMP)

	EXPAND(55); ROUND(SA, SB, SC, SD, SE, F3, TMP3, TMP)
	EXPAND(56); ROUND(SE, SA, SB, SC, SD, F3, TMP3, TMP)
	EXPAND(57); ROUND(SD, SE, SA, SB, SC, F3, TMP3, TMP)
	EXPAND(58); ROUND(SC, SD, SE, SA, SB, F3, TMP3, TMP)
	EXPAND(59); ROUND(SB, SC, SD, SE, SA, F3, TMP3, TMP)

	movl	K4VALUE, TMP2
	EXPAND(60); ROUND(SA, SB, SC, SD, SE, F2, TMP2, TMP)
	EXPAND(61); ROUND(SE, SA, SB, SC, SD, F2, TMP2, TMP)
	EXPAND(62); ROUND(SD, SE, SA, SB, SC, F2, TMP2, TMP)
	EXPAND(63); ROUND(SC, SD, SE, SA, SB, F2, TMP2, TMP)
	EXPAND(64); ROUND(SB, SC, SD, SE, SA, F2, TMP2, TMP)

	EXPAND(65); ROUND(SA, SB, SC, SD, SE, F2, TMP2, TMP)
	EXPAND(66); ROUND(SE, SA, SB, SC, SD, F2, TMP2, TMP)
	EXPAND(67); ROUND(SD, SE, SA, SB, SC, F2, TMP2, TMP)
	EXPAND(68); ROUND(SC, SD, SE, SA, SB, F2, TMP2, TMP)
	EXPAND(69); ROUND(SB, SC, SD, SE, SA, F2, TMP2, TMP)

	EXPAND(70); ROUND(SA, SB, SC, SD, SE, F2, TMP2, TMP)
	EXPAND(71); ROUND(SE, SA, SB, SC, SD, F2, TMP2, TMP)
	EXPAND(72); ROUND(SD, SE, SA, SB, SC, F2, TMP2, TMP)
	EXPAND(73); ROUND(SC, SD, SE, SA, SB, F2, TMP2, TMP)
	EXPAND(74); ROUND(SB, SC, SD, SE, SA, F2, TMP2, TMP)

	EXPAND(75); ROUND(SA, SB, SC, SD, SE, F2, TMP2, TMP)
	EXPAND(76); ROUND(SE, SA, SB, SC, SD, F2, TMP2, TMP)
	EXPAND(77); ROUND(SD, SE, SA, SB, SC, F2, TMP2, TMP)
	EXPAND(78); ROUND(SC, SD, SE, SA, SB, F2, TMP2, TMP)
	EXPAND(79); ROUND(SB, SC, SD, SE, SA, F2, TMP2, TMP)

	// Update the state vector
	movl	88(%esp),TMP
	addl	SA, (TMP) 
	addl	SB, 4(TMP) 
	addl	SC, 8(TMP) 
	addl	SD, 12(TMP) 
	addl	SE, 16(TMP)

	addl	$68, %esp
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret

//  It's possible to shave of half of the stores to tmp in the evaluation of f3,
//  although it's probably not worth the effort. This is the trick: 
//  
//  round(a,b,c,d,e,f,k) modifies only b,e.
//  
//  round(a,b,c,d,e,f3,k)
//  round(e,a,b,c,d,f3,k)
//  
//  ; f3(b,c,d) = (b & c) | (d & (b | c))
//  
//    movl b, tmp
//    andl c, tmp
//    movl tmp, tmp2
//    movl b, tmp
//    orl  c, tmp
//    andl d, tmp
//    orl tmp2, tmp
//  
//  and corresponding code for f3(a,b,c)
//  
//  Use the register allocated for c as a temporary?
//  
//    movl c, tmp2
//  ; f3(b,c,d) = (b & c) | (d & (b | c))
//    movl b, tmp
//    orl  c, tmp
//    andl b, c
//    andl d, tmp
//    orl  c, tmp
//  
//  ; f3(a,b,c) = (a & b) | (c & (a | b))
//    movl b, tmp
//    andl a, tmp
//    movl a, c
//    orl  b, c
//    andl tmp2, c
//    orl  c, tmp
//  
//    movl tmp2, c
//  
//  Before: 14 instr, 2 store, 2 load
//  After: 13 instr, 1 store, 2 load
//  
//  Final load can be folded into the next round,
//  
//  round(d,e,a,b,c,f3,k)
//  
//    c += d <<< 5 + f(e, a, b) + k + w
//  
//  if we arrange to have w placed directly into the register
//  corresponding to w. That way we save one more instruction, total save
//  of two instructions, one of which is a store, per two rounds. For the
//  twenty rounds involving f3, that's 20 instructions, 10 of which are
//  stores, or about 1.5 %.
