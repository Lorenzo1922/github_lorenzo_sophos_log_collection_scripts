#!/bin/sh
####################################
#
#xg basic log collector for wireless issues
#
####################################

#### function to kill jobs with trap ####
cleanup()
{
	echo "cleanup"
    kill -9 $program_1_pid          
    kill -9 $program_2_pid          
    kill -9 $program_3_pid  
    kill -9 $program_4_pid 
    kill -9 $program_5_pid
    kill -9 $program_6_pid
    kill -9 $program_7_pid
    kill -9 $program_8_pid
    kill -9 $program_9_pid

	exit	
}

#### exit when customer finished to replicate the issue early ####
echo "PRESS CTRL + C IF YOU WANT TO STOP THE SCRIPT"
trap cleanup SIGINT   

#### script guide ####
echo -en '\n'
echo -en '\n'
echo "HOW TO USE THE SCRIPT:"
echo "      - reply to the initial questions"
echo "      - press enter if you do not know the answer of the questions"
echo "      - do not type special characters in the answers and do not delete caracters. If so, then press CTRL + C and start the script again"
echo "      - press CTRL + C if you would like to stop the log collection"
echo "      - do not close the terminal till the script finishes to save the files"
echo "      - if you need to run the script multiple times, add different answers to the 1st question like <case_number>_test_2"
echo -en '\n'
echo -en '\n'

#### variables ####
read -p "Which is the sophos case number? " case_number
read -p "Whis is the source ip you are going to test? " source_ip
read -p "Whis is the destination ip you are going to test? " destination_ip
read -p "Which will be the tested destination port number? " dst_port
read -p "Which is the sophos ftp username? " ftp_username
read -p "Which is the sophos ftp password? " ftp_password 
read -p "How many seconds you need to replicate the issue? " time_to_test

echo I am creating a folder named $case_number
mkdir /tmp/$case_number

echo I am creating a report file with the commands used during the log collection named report_$case_number
touch /tmp/$case_number/report_$case_number.txt
echo log collection event details >> /tmp/$case_number/report_$case_number.txt
event_timestamp=$(date)
echo even details: >> /tmp/$case_number/report_$case_number.txt
echo timestamp = $event_timestamp >> /tmp/$case_number/report_$case_number.txt
echo tested source ip = $source_ip >> /tmp/$case_number/report_$case_number.txt
echo tested destination ip = $destination_ip >> /tmp/$case_number/report_$case_number.txt
echo tested destination port = $dst_port >> /tmp/$case_number/report_$case_number.txt

xg_incoming_interface=$(ip -o route get $source_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
echo the xg used incoming interface is $xg_incoming_interface

xg_outcoming_interface=$(ip -o route get $destination_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
echo the xg used outcoming interface is $xg_outcoming_interface

#### enable debug mode on modules ####
echo I am putting the following processes in debug mode
service ips:debug -ds nosync     
for x in /tmp/snort[0-9]* ; do daq_control $x 18 -text D4L7; done          
csc custom debug
ips_module_status=$(service -S | grep ips)
echo the ips module status is:  $'\n'$ips_module_status
access_server_status=$(service -S | grep access_server)
service access_server:debug -ds nosync
echo the access_server module is $'\n'$access_server_status
echo the csc module is in debug now

#### log collection commands ####
tcpdump -envvi $xg_incoming_interface host $source_ip and port $dst_port -s0 -w /tmp/$case_number/capture_xg_incoming_interface_$xg_incoming_interface_$(date +"%Y_%m_%d_%I_%M_%p").log.pcap -b &
program_1_pid=$! 

tcpdump -envvi $xg_outgoing_interface host $source_ip and port $dst_port -s0 -w /tmp/$case_number/capture_xg_incoming_interface_$xg_outgoing_interface_$(date +"%Y_%m_%d_%I_%M_%p").log.pcap -b &
program_2_pid=$! 

tcpdump -envvi any host $source_ip and host $destination_ip and port $dst_port -s0 -w /tmp/$case_number/capture_xg_any_interface_$(date +"%Y_%m_%d_%I_%M_%p").log.pcap -b &
program_3_pid=$!

conntrack -s $source_ip -E -o timestamp | awk -F "[\t]" '{ gsub(/(\[)/,"",$1) ;gsub(/(\])/,"",$1); print strftime("%c",$1) " " $2 }' > /tmp/$case_number/conntrack_xg_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_4_pid=$!

drppkt host $destination_ip > /tmp/$case_number/drppkt_xg_by_destination_ip_$destination_ip_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_5_pid=$!

tail -f /log/ips.log > /tmp/$case_number/ips_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_6_pid=$!

tail -f /log/access_server.log > /tmp/$case_number/access_server_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

tail -f /log/csc.log > /tmp/$case_number/csc_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_8_pid=$!

tail -f /log/awed.log > /tmp/$case_number/awed_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_9_pid=$!

sleep $time_to_test             #wait enough time for someone to replicate the issue

#### kill running jobs in background ####
kill -9 $program_1_pid          
kill -9 $program_2_pid          
kill -9 $program_3_pid  
kill -9 $program_4_pid 
kill -9 $program_5_pid 
kill -9 $program_6_pid
kill -9 $program_7_pid
kill -9 $program_8_pid
kill -9 $program_9_pid

#### remove debug mode from modules ####
for x in /tmp/snort[0-9]* ; do daq_control $x 18 -text D4L4 ; done       #to remove debug mode from ips module
service ips:debug -ds nosync                                             #to remove debug mode from ips module
#service access_server:debug -ds nosync                                   #to remove debug mode from access_server module

echo commands used during the log collection: >> /tmp/$case_number/report_$case_number.txt >> /tmp/$case_number/report_$case_number.txt
echo tcpdump -envvi $xg_incoming_interface host $source_ip and port $dst_port >> /tmp/$case_number/report_$case_number.txt 
echo tcpdump -envvi $xg_outgoing_interface host $source_ip and port $dst_port >> /tmp/$case_number/report_$case_number.txt
echo tcpdump -envvi any host $source_ip and host $destination_ip and port $dst_port >> /tmp/$case_number/report_$case_number.txt
echo conntrack -s $source_ip -E -o >> /tmp/$case_number/report_$case_number.txt
echo drppkt host $destination_ip >> /tmp/$case_number/report_$case_number.txt
echo tail -f /log/ips.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /log/access_server.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /log/csc.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /log/awed.log >> /tmp/$case_number/report_$case_number.txt 

#read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

#compress the folder to export
tar -czvf /tmp/${case_number}_compressed.tar.gz /tmp/$case_number

#### sends logs to sophos ftp server ####
echo "RUN THE FOLLOWING COMMANDS TO SEND THE LOGS TO SOPHOS FTP SERVER"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'