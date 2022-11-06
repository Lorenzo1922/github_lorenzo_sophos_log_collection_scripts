#!/bin/sh
####################################
#
#xg basic log collector to start your troubleshooting
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

	exit	
}

#### exit when customer finished to replicate the issue early ####
echo "PRESS CTRL + C IF YOU WANT TO STOP THE SCRIPT"
trap cleanup SIGINT 

#### what the script does ####
echo -en '\n'
echo "THIS SCRIPT WILL HELP YOU TROUBLESHOOTING MAIN ISSUE ON XG TO FIND LIKE RULE USED AND TCPDUMP ON AFFECTED INTERFACES"
echo -en '\n'

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
read -p "Whis is the firewall rule id number that supposed to allow the traffic? " firewall_rule_id
read -p "Whis is the DNAT rule id number that supposed to allow the traffic? " dnat_rule_id
read -p "Which is the sophos ftp username? " ftp_username
read -p "Which is the sophos ftp password? " ftp_password 
read -p "How many seconds you need to replicate the issue? " time_to_test

sleep 2
echo -en '\n'

xg_serial_number=$(nvram get  '#li.serial')
event_timestamp=$(date)
xg_incoming_interface=$(ip -o route get $source_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
xg_outgoing_interface=$(ip -o route get $destination_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')

echo I am creating a folder that will contain all the logs we will collect named: ${case_number}_${xg_serial_number}
mkdir /tmp/${case_number}_${xg_serial_number}

echo I am creating a report file that will contained all the info about what we tested named: sap_note_${case_number}_${xg_serial_number}
touch /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo -en '\n'

#### enable debug mode on modules ####
echo "I AM PUTTING THE FOLLOWING PROCESSES IN DEBUG MODE"
echo -en '\n'
echo IPS
service ips:debug -ds nosync     
for x in /tmp/snort[0-9]* ; do daq_control $x 18 -text D4L7; done          
csc custom debug
ips_module_status=$(service -S | grep ips)
echo the ips module status is:  $'\n'$ips_module_status

sleep 5
echo -en '\n'

#### log collection commands ####
echo I AM STARTING COLLECTING THE LOGS
echo -en '\n'
tcpdump -eni any -c 10000 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_any_host_any_port_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_1_pid=$!

tcpdump -envvi $xg_incoming_interface host $source_ip and port $dst_port -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_incoming_interface_${xg_incoming_interface}_source_ip_${source_ip}_and_dst_port_${dst_port}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_2_pid=$! 

tcpdump -envvi $xg_outgoing_interface host $source_ip and port $dst_port -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_outgoing_interface_${xg_outgoing_interface}_source_ip_${source_ip}_and_dst_port_${dst_port}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_3_pid=$! 

tcpdump -envvi any host $source_ip and host $destination_ip and port $dst_port -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_source_ip_${source_ip}_destination_ip_${destination_ip}_and_dst_port_${dst_port}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_4_pid=$!

conntrack -s $source_ip -E -o timestamp | awk -F "[\t]" '{ gsub(/(\[)/,"",$1) ;gsub(/(\])/,"",$1); print strftime("%c",$1) " " $2 }' > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_xg_filtered_by_source_ip_${source_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_5_pid=$!

drppkt host $source_ip > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_filtred_by_source_ip_${source_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_6_pid=$!

drppkt host $destination_ip > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_filtred_by_destination_ip_${destination_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

tail -f /log/ips.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_ips_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_8_pid=$!

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

#### remove debug mode from modules ####
echo -en '\n'
echo "I AM REMOVING THE FOLLOWING PROCESSES FROM DEBUG"

echo -en '\n'
echo IPS
for x in /tmp/snort[0-9]* ; do daq_control $x 18 -text D4L4 ; done       #to remove debug mode from ips module
service ips:debug -ds nosync                                             #to remove debug mode from ips module

### info to add into the sap note ####
echo -en '\n'
echo ---- SAP NOTE CASE $case_number ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      issue description" = >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      error message" =  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- DATA ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      new configuration" =  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      serial number = $xg_serial_number" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      product  = $(cish -c system diagnostics show version-info | grep "Appliance Model" | awk {'print $3'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      firmware version  = $(cish -c system diagnostics show version-info | grep "Firmware Version" | awk {'print $4'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      access id | how long it last | when it was enabled = $(psql -U nobody -d corporate -c "select * from tblsupportaccess" | grep "sophos.com")" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      customer phone number  =" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      sophos ftp credentials  = $ftp_username:$ftp_password" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      frequency of the issue  =" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      customer language = english" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      firewall rule that supposed to allow the traffic = id $firewall_rule_id" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      firewall DNAT rule that suppose to allow the traffic  = id $dnat_rule_id" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- LOG COLLECTION EVENT DETAILS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      timestamp = $event_timestamp" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested source ip = $source_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          the xg reaches the source ip using the incoming interface = $xg_incoming_interface" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested destination ip = $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          the xg reaches the destination ip using the outcoming interface = $xg_outgoing_interface" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- ASSESSMENT ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      What you think the real problem is" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- TROUBLESHOOTING STEPS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      replicated the issue collecting the logs" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check routing order" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cish -c system route_precedence show >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check if firewall acceleration is enabled" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cish -c system firewall-acceleration show >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check if there is bypass rules configured" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cish -c show advanced-firewall >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ----  POA  ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      Plan of action with next steps clearly stated on the ticket" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- COMMANDS USED DURING THE LOG COLLECTION ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -eni any -c 10000" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_incoming_interface host $source_ip and port $dst_port" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_outgoing_interface host $source_ip and port $dst_port" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi any host $source_ip and host $destination_ip and port $dst_port" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      conntrack -s $source_ip -E" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      drppkt host $source_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      drppkt host $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/ips.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- COLLECTED LOG FILENAMES ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
search_dir=/tmp/${case_number}_${xg_serial_number}/
for file in $search_dir*;
do
  echo "    ${file##*/}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
done
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- LOG ANALYSIS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check conntrack filtering by source ip ${source_ip} and destination port ${dst_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_xg_filtered_by_source_ip_${source_ip}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check dropped packets filtering by source ip ${source_ip}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_filtred_by_source_ip_${source_ip}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check dropped packets filtering by destination ip ${destination_ip}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_filtred_by_destination_ip_${destination_ip}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check packet capture filtered by xg incoming interface ${xg_incoming_interface} and source ip ${source_ip} and dst port ${dst_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -qns 0 -A -r /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_incoming_interface_${xg_incoming_interface}_source_ip_${source_ip}_and_dst_port_${dst_port}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check packet capture filtered by xg outgoing interface ${xg_outgoing_interface} and source ip ${source_ip} and dst port ${dst_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -qns 0 -A -r /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_outgoing_interface_${xg_outgoing_interface}_source_ip_${source_ip}_and_dst_port_${dst_port}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check packet capture filtered by source ip ${source_ip} and destination ip ${destination_ip} and dst port ${dst_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -qns 0 -A -r /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_source_ip_${source_ip}_destination_ip_${destination_ip}_and_dst_port_${dst_port}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

#### compress everything ####
tar -czvf /tmp/${case_number}_${xg_serial_number}_compressed.tar.gz /tmp/${case_number}_${xg_serial_number}/ > /dev/null 2>&1        #compress the folder to export

#### sends logs to sophos ftp server ####
echo "RUN THE FOLLOWING COMMANDS TO SEND THE LOGS TO SOPHOS FTP SERVER"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_${xg_serial_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'

#### display the sap note ####
echo -en '\n'
echo -en '\n'
echo SCRATCH SAP NOTE
echo -en '\n'
cat /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 

#### sends logs to sophos ftp server ####
echo "RUN THE FOLLOWING COMMANDS TO SEND THE LOGS TO SOPHOS FTP SERVER"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_${xg_serial_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'

#### other logs to collect ####
echo "IN CASE YOU WOULD LIKE TO COLLECT A LOG DUMP YOU CAN USE THIS COMMAND"
echo "tar -czvf /tmp/logbundle_$(date +"%Y_%m_%d_%I_%M_%p").tar.gz /log/*.log"
echo -en '\n'
echo -en '\n'