# PROCESS_ENABLE_VAR([SHELL_VAR], [AUTOMAKE_VAR], [MESSAGE])
# ----------------------------------------------------------
AC_DEFUN([PROCESS_ENABLE_VAR], [
	AC_MSG_CHECKING($3)
	if test x$1 = xyes; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi
	AM_CONDITIONAL($2, [test x$1 = xyes])
])
