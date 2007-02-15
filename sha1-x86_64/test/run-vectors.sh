#!/bin/sh

DEV=/dev/sha1test
CONV=./hextostream
MONTE=./monte

processMessageFile() {
	file="$1"
	echo "Processing $file"
	cat $DEV > /dev/null
	while read key equals value
	do
		case "$key" in
		Len)
			curlen="$value"
			;;
		Msg)
			# The Msg field for the zero-length message test
			# contains a zero byte, so we have to pay attention to
			# the length field in this case
			if [ $curlen = 0 ] ; then
				value=""
			fi
			echo "$value" | $CONV > $DEV
			;;
		MD)
			result=`cat $DEV`
			if [ "$result" = "$value" ] ; then
				passed=$(($passed + 1))
			else
				failed=$(($failed + 1))
				echo "Len $curlen: fail"
			fi
			;;
		esac
	done < $file
}

processMonteFile() {
	file="$1"
	echo "Processing $file"
	cat $DEV > /dev/null
	while read key equals value
	do
		case "$key" in
		Seed)
			seed="$value"
			count=0
			;;
		COUNT)
			if [ $count != "$value" ] ; then
				echo "Counter desynchronized; giving up"
				return
			fi
			result=`$MONTE $DEV "$seed"`
			;;
		MD)
			if [ "$result" = "$value" ] ; then
				passed=$(($passed + 1))
			else
				failed=$(($failed + 1))
				echo "Monte count $count: fail"
			fi
			seed="$value"
			count=$(($count + 1))
			;;
		esac
	done < $file
}

processLargeFile() {
	# Check for rollover problems between the low word and high word
	# of the bit counter in the last block (at 512 MB boundary)
	
	echo "Processing large file"
	dd if=/dev/zero of=$DEV bs=1048576 count=800 2> /dev/null
	result=`cat $DEV`
	if [ "$result" = "837b0910bd47c4dfb20d36b759beb4a73edc4a93" ] ; then
		passed=$(($passed + 1))
	else
		failed=$(($failed + 1))
		echo "Large file test: fail"
	fi
}

if [ ! -e $DEV ] ; then
	echo "$DEV does not exist"
	exit 1
fi

if [ ! -x $CONV ] ; then
	echo "$CONV does not exist; try 'make'"
	exit 1
fi

if [ ! -x $MONTE ] ; then
	echo "$MONTE does not exist; try 'make'"
	exit 1
fi

passed=0
failed=0
processMessageFile vectors/SHA1ShortMsg.txt
processMessageFile vectors/SHA1LongMsg.txt
processMonteFile vectors/SHA1Monte.txt
processLargeFile
echo "$passed tests passed, $failed failed"
