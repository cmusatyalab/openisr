changequote(<,>)dnl

dnl FORTRAN style comment character
define(<C>, <
dnl>)dnl

define(<PROLOGUE>,
<ifelse(ELF_STYLE,yes,
<.globl C_NAME($1)
.type C_NAME($1),TYPE_FUNCTION
C_NAME($1):>,
<.globl C_NAME($1)
C_NAME($1):>)>)

define(<EPILOGUE>,
<ifelse(ELF_STYLE,yes,
<.L$1end:
.size C_NAME($1), .L$1end - C_NAME($1)>,)>)

