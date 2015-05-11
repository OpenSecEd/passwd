#!/usr/bin/env python
# $Id$

# Copyright (c) 2012, Daniel Bosk <daniel.bosk@miun.se>.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
#
# *  Redistributions of source code must retain the above copyright notice, 
#   list of conditions and the following disclaimer.
# *  Redistributions in binary form must reproduce the above copyright notice, 
#   this list of conditions and the following disclaimer in the documentation 
#   and/or other materials provided with the distribution.
# *  Neither the name of the author nor the names of other contributors may be 
#  used to endorse or promote products derived from this software without 
#  specific prior written permission.
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

import argparse, sys, threading, string, Queue, math, random

verbose = False

# variable to parallelise sequential execution
seqgen_current_top = []
# lock for the above variable
seqgen_lock = threading.Lock()


# helper function for extend_password()
def update_letter(passwd, alphabet, index):
  if ( index < 0 ):
    # we had an overflow in the last letter, add another letter
    passwd.append( alphabet[0] )
    return passwd

  # increase the letter at index
  c = passwd[index]
  idx = ( alphabet.index(c) + 1 ) % len(alphabet)
  c = alphabet[idx]
  passwd[index] = c

  if ( idx == 0 ):
    # there was an overflow for current index, add to next index
    passwd = update_letter(passwd, alphabet, index-1)
  
  return passwd

# "increase password by one", return the next password in sequential order
def extend_passwd(passwd, alphabet):
  return update_letter(passwd, alphabet, len(passwd)-1)


# add 50000 to top in base len(alphabet)
def seqgen_new_top(top, alphabet):
  # every thread generates 50000 passwords
  n = 50000
  base = len(alphabet)
  digits = []
  
  # compute 50000 in base len(alphabet)
  while ( n > 0 ):
    digits.append( n % base )
    n = n // base

  i = 0
  # add all digits
  while ( i < len(digits) ):
    if ( len(digits) > len(top) ):
      # make sure top has enough digits
      top = [ alphabet[0] ] * ( len(digits) - len(top) ) + top

    # find the value of the current digit in top
    idx = alphabet.index( top[len(top)-1-i] )
    # add the digits together
    new_idx = ( idx + digits[i] )
    
    # see if we had an overflow
    if ( new_idx >= base ):
      if ( i+1 >= len(digits) ):
        digits.append(0)
      # move overflow to next digit
      digits[i+1] += new_idx // base
      # keep remainder
      new_idx %= base

    # replace the digit
    top[len(top)-1-i] = alphabet[new_idx]
    i += 1

  return top


def sequential_generator(alphabet, min_length, max_length, passwd_queue):
  global seqgen_current_top, seqgen_lock

  # allocate an interval of passwords to process in this thread
  seqgen_lock.acquire()
  if ( len(seqgen_current_top) > max_length ):
    seqgen_lock.release()
    return
  passwd = extend_passwd( list(seqgen_current_top), alphabet )
  seqgen_current_top =  seqgen_new_top( seqgen_current_top, alphabet )
  top = list( seqgen_current_top )
  sys.stderr.write("new top %s." % ( top ) )
  seqgen_lock.release()

  # produce passwords
  while ( len(passwd) <= max_length or max_length < 1 and \
      passwd != top ):
    passwd_queue.put( list(passwd) )
    if ( verbose ):
      sys.stderr.write("added %s to queue (%d).\n" % \
        ( passwd, passwd_queue.qsize() ))
    passwd = extend_passwd( passwd, alphabet )


def random_generator(alphabet, min_length, max_length, passwd_queue):
  while ( True ):
    passwd = []
    # find a random length within our limits
    n = random.randint(min_length, max_length)

    # choose n letters from the alphabet
    for _ in range(n):
      passwd.append( random.choice(alphabet) )

    passwd_queue.put( passwd )
    if ( verbose ):
      sys.stderr.write("added %s to queue (%d).\n" % \
        ( passwd, passwd_queue.qsize() ))


# take a list of files and read one word per line in these into a list
def load_wordlist(files):
  wordlist = []
  for filename in files:
    f = open(filename, "r")
    for line in f.readlines():
      wordlist.append( line.strip() )
    f.close()
  return wordlist


def main(argv):
  # the default alphabet to be used
  alphabet = "abcdefghijklmnopqrstuvwxyz"
  alphabet += alphabet.upper()
  alphabet += "0123456789 !@#$%&/()=-.,?+"

  # a parser for the command line
  argp = argparse.ArgumentParser( \
      description = "Generate a stream of passwords." )

  # add arguments
  argp.add_argument("-m", "--minlen", default = 1, type = int, \
      help = "minimum password length to try, " +\
      "default %(default)d.")
  argp.add_argument("-M", "--maxlen", default = 0, type = int, \
      help = "maximum password length to try, default infinite.")
  argp.add_argument("-t", "--threads", default = 4, type = int, \
      help = "number of threads to use for execution, " + \
      "default %(default)d.")
  argp.add_argument("-q", "--qsize", default = 100, type = int, \
      help = "maximum queue size for password generator thread, " + \
      "default %(default)d.")
  argp.add_argument("-r", "--random", action="store_true", \
      help = "randomise password generation, " + \
      "default is to generate them sequentially.")
  argp.add_argument("-a", "--alphabet", default = alphabet, \
      help = "set the alphabet to be used, default: %(default)s.")
  argp.add_argument("-w", "--wordlist", nargs = "+", default = None, \
      help = "use wordlist mode, i.e. use words from supplied " + \
      "wordlist(s) as alphabet.  This overrides --alphabet.")
  argp.add_argument("-v", "--verbose", action = "store_true", \
      help = "enable verbose output to stderr.")

  # process the commmand line
  args = vars( argp.parse_args(argv[1:]) )

  alphabet = args["alphabet"]
  min_length = args["minlen"]
  max_length = args["maxlen"]
  num_threads = args["threads"]
  threads = []
  queue_size = args["qsize"]
  passwd_queue = Queue.Queue( queue_size )
  passwd_generator = sequential_generator
  run_sequentially = True
  if ( args["random"] ):
    run_sequentially = False
    passwd_generator = random_generator
  use_wordlist = ( args["wordlist"] != None )
  if ( use_wordlist ):
    alphabet = load_wordlist( args["wordlist"] )
  global verbose
  verbose = args["verbose"]

  # start a password generator thread
  t = threading.Thread( target = passwd_generator, \
      args = ( alphabet, min_length, max_length, passwd_queue ) )
  t.start()
  threads.append(t)
  if ( verbose ):
    sys.stderr.write("started generator thread (%d)\n" % \
        ( len(threads) ))

  i = 0
  # run as long as we have threads running or the password queue is not empty
  while ( len(threads) > 0 or not passwd_queue.empty() ):
    # if we have threads running, see if they are still running
    if ( len(threads) > 0 ):
      i = (i + 1) % len(threads)
      if ( not threads[i].is_alive() ):
        # remove dead thread
        threads.pop(i)
        if ( verbose ):
          sys.stderr.write("removed generator thread (%d)\n" % \
              ( len(threads) ))
        # we want to remove all dead threads
        continue

    # if the queue is less than 50% full, start another thread to produce 
    # passwords
    if ( passwd_queue.qsize() < math.ceil( 0.50 * queue_size ) and \
        ( len(threads) < num_threads or num_threads < 1 ) ):
      t = threading.Thread( target = passwd_generator, \
          args = ( alphabet, min_length, max_length, passwd_queue ) )
      t.start()
      threads.append(t)
      if ( verbose ):
        sys.stderr.write("started generator thread (%d)\n" % \
            ( len(threads) ))

    # get and print a password from the password queue
    try:
      # block for at most 0.1 seconds
      passwd = passwd_queue.get(True, 0.1)
    except Queue.Empty as e:
      continue
    
    # print password to stdout, if we use wordlists print both with and 
    # without spaces
    s = passwd[0]
    for t in passwd[1:]:
      if ( use_wordlist ):
        s += " "
      s += str(t)
    sys.stdout.write("%s\n" % (s))
    if ( use_wordlist ):
      sys.stdout.write("%s\n" % ( s.replace(" ", "") ))
    passwd_queue.task_done()

  return 0


if __name__ == "__main__":
  sys.exit( main( sys.argv ) )
