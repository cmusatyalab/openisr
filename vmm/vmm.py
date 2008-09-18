import os
import sys
import subprocess
import stat
import __main__

__all__ = 'VmmError', 'main', 'have_program', 'run_program'

class VmmError(Exception):
	def __init__(self, message):
		self.message = message
	def __str__(self):
		return self.message

def _init():
	global VMNAME

	VMNAME = "UnknownVMM"
	for var in 'NAME', 'CFGDIR', 'UUID', 'DISK', 'SECTORS', 'MEM', \
				'FULLSCREEN', 'SUSPENDED', 'COMMAND':
		if os.environ.has_key(var):
			exec('global ' + var + ';' + var + ' = "' + \
						os.environ[var] + '"')

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
			print "RUNNABLE_REASON=%s: %s" % \
						(inst.__class__.__name__, inst)
		else:
			print "VMM=%s" % VMNAME
			print "RUNNABLE=yes"
	elif sys.argv[1] == "run":
		try:
			__main__.run()
		except Exception, inst:
			print "SUSPENDED=%s" % SUSPENDED
			print "SUCCESS=no"
			print "ERROR=%s: %s" % (inst.__class__.__name__, inst)
		else:
			print "SUSPENDED=%s" % SUSPENDED
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

# Returns true if prog is executable (directly if absolute path, via PATH if
# not)
def have_program(prog):
	if prog[0] == '/':
		return _executable(prog)
	for dirname in os.environ['PATH'].split(':'):
		path = dirname + '/' + prog
		if _executable(path):
			return True
	return False

# Run a process and wait for it to complete, redirecting its stdout to stderr
# so that the child can't write key-value pairs back to our calling process
def run_program(*args):
	return subprocess.call(args, stdout = sys.stderr)

_init()
