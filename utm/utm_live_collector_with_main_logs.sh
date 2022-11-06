#!/bin/sh
####################################
#
#utm log collector for main logs small change
#
####################################

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
read -p "How many seconds you need to replicate the issue? " time_to_test

echo I am creating a folder named $case_number
mkdir /tmp/$case_number

echo I am creating a report file with the commands used during the log collection named report_$case_number
touch /tmp/$case_number/report_$case_number.txt
echo log collection event details >> /tmp/$case_number/report_$case_number.txt
event_timestamp=$(date)
echo event details: >> /tmp/$case_number/report_$case_number.txt
echo timestamp = $event_timestamp >> /tmp/$case_number/report_$case_number.txt
echo tested source ip = $source_ip >> /tmp/$case_number/report_$case_number.txt
echo tested destination ip = $destination_ip >> /tmp/$case_number/report_$case_number.txt
echo tested destination port = $dst_port >> /tmp/$case_number/report_$case_number.txt

utm_incoming_interface=$(ip -o route get $source_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
echo the utm used incoming interface is $utm_incoming_interface

utm_outgoing_interface=$(ip -o route get $destination_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
echo the utm used outcoming interface is $utm_outgoing_interface

#### enable debug mode on modules ####   

#### log collection commands ####
tcpdump -envvi $utm_incoming_interface host $source_ip and port $dst_port -s0 -w /tmp/$case_number/capture_utm_incoming_interface_$utm_incoming_interface$(date +"%Y_%m_%d_%I_%M_%p").log.pcap -b &
program_1_pid=$! 

tcpdump -envvi $utm_outgoing_interface host $source_ip and port $dst_port -s0 -w /tmp/$case_number/capture_utm_incoming_interface_$utm_outgoing_interface$(date +"%Y_%m_%d_%I_%M_%p").log.pcap -b &
program_2_pid=$! 

tcpdump -envvi any host $source_ip and host $destination_ip and port $dst_port -s0 -w /tmp/$case_number/capture_utm_any_interface_$(date +"%Y_%m_%d_%I_%M_%p").log.pcap -b &
program_3_pid=$!

tail -f /var/log/packetfilter.log > /tmp/$case_number/packetfilter_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_4_pid=$!

tail -f /var/log/confd.log > /tmp/$case_number/confd_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_5_pid=$!

tail -f /var/log/confd-debug.log > /tmp/$case_number/confd-debug_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_6_pid=$!

tail -f /var/log/fallback.log > /tmp/$case_number/fallback_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

tail -f /var/log/kernel.log > /tmp/$case_number/kernel_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_8_pid=$!

tail -f /var/log/mdw.log > /tmp/$case_number/mdw_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_9_pid=$!

tail -f /var/log/system.log > /tmp/$case_number/system_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_10_pid=$!

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
kill -9 $program_10_pid

#### save in the report file the commands I did use ####
echo commands used during the log collection: >> /tmp/$case_number/report_$case_number.txt >> /tmp/$case_number/report_$case_number.txt
echo tcpdump -envvi $utm_incoming_interface host $source_ip and port $dst_port >> /tmp/$case_number/report_$case_number.txt 
echo tcpdump -envvi $utm_outgoing_interface host $source_ip and port $dst_port >> /tmp/$case_number/report_$case_number.txt
echo tcpdump -envvi any host $source_ip and host $destination_ip and port $dst_port >> /tmp/$case_number/report_$case_number.txt
echo tail -f /var/log/packetfilter.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /var/log/confd.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /var/log/confd-debug.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /var/log/fallback.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /var/log/kernel.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /var/log/mdw.log >> /tmp/$case_number/report_$case_number.txt
echo tail -f /var/log/system.log >> /tmp/$case_number/report_$case_number.txt

#read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

#compress the folder to export
tar -czvf /tmp/${case_number}_$(date +%F-%H:%M:%S).tar.gz /tmp/$case_number/

#### remove debug mode from modules ####           

#tar -czvf /tmp/logbundle_$(date +"%Y_%m_%d_%I_%M_%p").tar.gz /var/log/*.log
#sh /usr/local/bin/get-support-data.sh 1