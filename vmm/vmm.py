#
# vmm.py - Helper code for OpenISR (R) VMM drivers written in Python
#
# Copyright (C) 2008 Carnegie Mellon University
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2 of the GNU General Public License as published
# by the Free Software Foundation.  A copy of the GNU General Public License
# should have been distributed along with this program in the file
# LICENSE.GPL.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#

import os
import sys
import subprocess
import stat
import traceback
import __main__

__all__ = 'VmmError', 'main', 'find_program', 'run_program'

VMNAME = "UnknownVMM"
DEBUG = False

class VmmError(Exception):
	def __init__(self, message):
		self.message = message
	def __str__(self):
		return self.message

def _init():
	for var in 'NAME', 'CFGDIR', 'UUID', 'DISK', 'SECTORS', 'MEM', \
				'FULLSCREEN', 'SUSPENDED', 'COMMAND':
		if os.environ.has_key(var):
			exec('global ' + var + ';' + var + ' = "' + \
						os.environ[var] + '"')

def _exception_msg(inst):
	if DEBUG:
		traceback.print_exc()
	if inst.__class__ == VmmError:
		return str(inst)
	else:
		return "%s: %s" % (inst.__class__.__name__, inst)

def main():
	if len(sys.argv) <= 1:
		print >>sys.stderr, "No mode specified"
		sys.exit(1)
	elif sys.argv[1] == "info":
		try:
			__main__.info()
		except Exception, inst:
			print "VMM=%s" % VMNAME
			print "RUNNABLE=no"
			print "RUNNABLE_REASON=%s" % _exception_msg(inst)
		else:
			print "VMM=%s" % VMNAME
			print "RUNNABLE=yes"
	elif sys.argv[1] == "run":
		try:
			__main__.run()
		except Exception, inst:
			print "SUSPENDED=%s" % SUSPENDED
			print "SUCCESS=no"
			print "ERROR=%s" % _exception_msg(inst)
		else:
			print "SUSPENDED=%s" % SUSPENDED
			print "SUCCESS=yes"
	elif sys.argv[1] == "cleanup":
		try:
			__main__.cleanup()
		except Exception, inst:
			print "SUCCESS=no"
			print "ERROR=%s" % _exception_msg(inst)
		else:
			print "SUCCESS=yes"
	else:
		print >>sys.stderr, "Unknown mode specified"
		sys.exit(1)
	sys.exit(0)

def _executable(path):
	try:
		st = os.stat(path)
	except OSError:
		return False
	return st[stat.ST_MODE] & stat.S_IXUSR|stat.S_IXGRP|stat.S_IXOTH > 0

# If prog is an absolute path and executable, return it.  If it is a relative
# path and executable via PATH, return the absolute path to the executable.
# If no executable is found, return false.
def find_program(prog):
	if prog[0] == '/':
		if _executable(prog):
			return prog
		else:
			return False
	for dirname in os.environ['PATH'].split(':'):
		path = dirname + '/' + prog
		if _executable(path):
			return path
	return False

# Run a process and wait for it to complete, redirecting its stdout to stderr
# so that the child can't write key-value pairs back to our calling process
def run_program(*args):
	return subprocess.call(args, stdout = sys.stderr)

_init()
