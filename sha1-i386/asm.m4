changequote(<,>)dnl

dnl FORTRAN style comment character
define(<C>, <
dnl>)dnl

define(<PROLOGUE>,
<.globl $1
.type $1,%function
$1:>)

define(<EPILOGUE>,
<.L$1end:
.size $1, .L$1end - $1>)

