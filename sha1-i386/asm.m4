changequote(<,>)dnl

dnl FORTRAN style comment character
define(<C>, <
dnl>)dnl

define(<PROLOGUE>,
<.globl C_NAME($1)
.type C_NAME($1),%function
C_NAME($1):>)

define(<EPILOGUE>,
<.L$1end:
.size C_NAME($1), .L$1end - C_NAME($1)>)

