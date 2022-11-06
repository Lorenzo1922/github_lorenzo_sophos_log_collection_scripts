#!/bin/sh

# Usage
# ./collect_tcpsump.sh <install|uninstall> <interface type>  <directory for data> <tcpdump option>
# ./collect_tcpsump.sh install  etc  /tmp/ducle-sophos
#     To install tcpdump for all interfaces of this type 'eth'
# ./collect_tcpsump.sh uninstall etc /tmp/ducle-sophos
#     To uninstall tcpdump for all interfaces of this type 'eth'
#

#how to use it - sample command
#./collect_tcpdump.sh install eth /tmp/ducle-sophos "src 212.118.198.37 and dst 212.118.198.37 and dst port 443"


INSTALL="$1"
ITF_TYPE="$2"
DIR="$3/data"
TCPDUMP_OPT="$4"
mkdir $DIR > /dev/null 2>&1

ulimit -f 1000                  #this set the amout of mb for the collection, 1000 = 1mb,so 200mb are 200x1000

if [ "$INSTALL" == "install" ]
then
  ifconfig | grep "Link encap" | grep $ITF_TYPE | grep -v "^$ITF_TYPE[0-9]*\." | awk '{print $1}' > $DIR/interfaces_for_collecting.txt

  echo "Installing..."
  while IFS= read -r itf
  do
    echo "Installing tcpdump for $itf"
    if [ "$TCPDUMP_OPT" == "" ]
    then
      tcpdump -i $itf -n -w $DIR/$itf.1MB.pcap > /dev/null 2>&1 &
    else
      tcpdump -i $itf $TCPDUMP_OPT -n -w $DIR/$itf.1MB.pcap > /dev/null 2>&1 &
    fi 
  done < $DIR/interfaces_for_collecting.txt
  echo
  echo "Tcpdump Listing"
  ps -elaf |grep tcpdump | grep -v grep | grep -v collect_tcpdump.sh
  echo
  echo
  echo "Tcpdump data will be in $DIR"
else
  echo "Uninstalling..."
  while IFS= read -r itf
  do
    if [ "$TCPDUMP_OPT" == "" ]
    then
      tcpdump_pid=`ps -elaf | grep -E "tcpdump -i $itf -n -w $DIR/$itf.1MB.pcap" | grep -v grep | awk '{print $4}'`
    else
      tcpdump_pid=`ps -elaf | grep -E "tcpdump -i $itf $TCPDUMP_OPT -n -w $DIR/$itf.1MB.pcap" | grep -v grep | awk '{print $4}'`
    fi
    echo "Uninstall tcpdump for $itf $tcpdump_pid"
    kill -9 $tcpdump_pid > /dev/null 2>&1
  done < $DIR/interfaces_for_collecting.txt

  echo
  echo "Tcpdump Listing"
  ps -elaf |grep tcpdump | grep -v grep | grep -v collect_tcpdump.sh
  echo
  echo

fi
