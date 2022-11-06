#!/bin/sh
####################################
#
#xg basic log collector for heartbeat issues
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
    kill -9 $program_10_pid
    kill -9 $program_11_pid
    kill -9 $program_12_pid
    kill -9 $program_13_pid

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
read -p "Whis is the user username you are going to test? " affected_username
read -p "Whis is the source ip you are going to test? " source_ip
read -p "How the affected user is connected to the firewall (lan, vpn, ect...)? " source_to_xg
read -p "Whis is the url you are going to test? " url
read -p "Which will be the tested destination port number? " tested_dst_port
read -p "Whis is the destination ip you are going to test (nslookup domain)? " destination_ip
read -p "Which is the sophos central remote access UID number? " sophos_central_UID
read -p "If you are using the xg as web proxy which is the port number (3128 or 8080 etc...)? " proxy_port
read -p "Which is the browser name you are going to use for the test? " browser_name
read -p "Which is the firewall rule id number that supposed to allow the traffic with Match known user enabled? " firewall_rule_id
read -p "Are you using other authentication methods at the same time with SATC and if yes which one? " other_authentication_methods
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

echo I am creating a report file that will contained all the info about what we tested named: report_${case_number}_${xg_serial_number}
touch /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo -en '\n'

#### enable debug mode on modules ####
echo "I AM PUTTING THE FOLLOWING PROCESSES IN DEBUG MODE"
echo -en '\n'

echo HEARTBEAT
service fwcm-heartbeatd:debug -ds nosync
service -t json -b '{"debug":"2"}' -ds nosync heartbeat:debug 

echo -en '\n'
echo IPS
service ips:debug -ds nosync     
for x in /tmp/snort[0-9]* ; do daq_control $x 18 -text D4L7; done          
ips_module_status=$(service -S | grep ips)
echo the ips module status is:  $'\n'$ips_module_status

echo -en '\n'
echo ACCESS SERVER
service access_server:debug -ds nosync
access_server_status=$(service -S | grep access_server)
echo the access sever status is: $'\n'$access_server_status

echo -en '\n'
echo AWARRENHTTP
service -ds nosync awarrenhttp:debug 
awarrenhttp_status=$(service -S | grep awarrenhttp)
echo the access sever status is: $'\n'$awarrenhttp_status

#### log collection commands ####
echo -en '\n'
tcpdump -envvi $xg_incoming_interface host $source_ip and port $tested_dst_port -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_incoming_interface_${xg_incoming_interface}_source_ip_${source_ip}_and_tested_destination_port_${tested_dst_port}_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_1_pid=$! 

tcpdump -envvi $xg_incoming_interface host $source_ip and host $destination_ip and port $tested_dst_port -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_incoming_interface_${xg_incoming_interface}_source_ip_${source_ip}_and_destination_ip_${destination_ip}_and_tested_destination_port_${tested_dst_port}_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_2_pid=$!

tcpdump -envvi $xg_outgoing_interface host $source_ip and port $tested_dst_port -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_outgoing_interface_${xg_outgoing_interface}_source_ip_${source_ip}_and_tested_destination_port_${tested_dst_port}_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_3_pid=$! 

tcpdump -envvi any host $source_ip and host $destination_ip and port $tested_dst_port -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_source_ip_${source_ip}_and_destination_ip_${destination_ip}_and_tested_destination_port_${tested_dst_port}_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_4_pid=$!

tcpdump -envvi $xg_incoming_interface host $source_ip and port 8347 -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_incoming_interface_${xg_incoming_interface}_source_ip_${source_ip}_and_heartbeat_port_8347_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_5_pid=$!

tcpdump -envvi $xg_outgoing_interface host $source_ip and port 8347 -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_outgoing_interface_${xg_outgoing_interface}_source_ip_${source_ip}_and_heartbeat_port_8347_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_6_pid=$! 

conntrack -s $source_ip -E -o timestamp | awk -F "[\t]" '{ gsub(/(\[)/,"",$1) ;gsub(/(\])/,"",$1); print strftime("%c",$1) " " $2 }' > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_filtered_by_source_ip_${$source_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

drppkt host $destination_ip > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_dropped_packets_filtered_by_destination_ip_${destination_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_8_pid=$!

tail -f /log/heartbeatd.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_heartbeatd_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_9_pid=$!

tail -f /log/access_server.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_10_pid=$!

tail -f /log/hbtrust.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_hbtrust_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_11_pid=$!

tail -f /log/awarrenhttp_access.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_awarrenhttp_access_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_12_pid=$!

tail -f /log/ips.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_ips_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_13_pid=$!

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
kill -9 $program_11_pid
kill -9 $program_12_pid
kill -9 $program_13_pid

#### remove debug mode from modules ####
service fwcm-heartbeatd:debug -ds nosync
service -t json -b ‘{“debug”:”0”}’ -ds nosync heartbeat:debug            #to remove debug mode from heatbeat module
for x in /tmp/snort[0-9]* ; do daq_control $x 18 -text D4L4 ; done       #to remove debug mode from ips module
service ips:debug -ds nosync                                             #to remove debug mode from ips module
service access_server:debug -ds nosync                                   #to remove debug mode from access_server module
service -ds nosync awarrenhttp:debug                                     #to remove debug mode from awarrenhttp module

echo -en '\n'

### info to add into the sap note ####
echo ---- SAP Case $case_number ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      issue description" = >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      error message" =  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- DATA ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      new configuration" =  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      serial number = $xg_serial_number" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      product  = $(cish -c system diagnostics show version-info | grep "Appliance Model" | awk {'print $3'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      firmware version  = $(cish -c system diagnostics show version-info | grep "Firmware Version" | awk {'print $4'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      access id  = $(psql -U nobody -d corporate -c "select * from tblsupportaccess" | grep "sophos.com")" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      customer phone number  =" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      sophos ftp credentials  = $ftp_username:$ftp_password" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      frequency of the issue  =" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      customer language = english" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      sophos central remote access UID number = ${sophos_central_UID}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      proxy port number configure = ${proxy_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      browser tested = ${browser_name}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      firewall rule id that supposed to allow the traffic = ${firewall_rule_id}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      is customer using other authentication methods = ${other_authentication_methods}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- LOG COLLECTION EVENT DETAILS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      timestamp = ${event_timestamp}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested user username = ${affected_username}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      testes source ip = ${source_ip}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      how the affected user is connected to the firewall = ${source_to_xg}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested url = ${url}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested destination port (from url) = ${dst_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested destination ip = ${destination_ip}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      proxy port (if configured) = ${proxy_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested browser name = ${browser_name}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested destination port = ${dst_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- ASSESSMENT ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      What you think the real problem is" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- TROUBLESHOOTING STEPS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      replicated the issue collecting the logs" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check the group name in which the user is in" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "        psql -U nobody -d corporate -c 'SELECT tbluser.name, tblusergrouprel.groupid FROM tbluser INNER JOIN tblusergrouprel ON tbluser.userid=tblusergrouprel.userid' | grep ${affected_username}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "             name             |                              groupname "  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
psql -U nobody -d corporate -c 'SELECT tbluser.name, tblusergrouprel.groupid FROM tbluser INNER JOIN tblusergrouprel ON tbluser.userid=tblusergrouprel.userid' | grep ${affected_username}
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

echo ---- COMMANDS USED DURING THE LOG COLLECTION ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_incoming_interface host $source_ip and port $tested_dst_port -s0 -w" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_incoming_interface host $source_ip and host $destination_ip and port $tested_dst_port -s0 -w" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_outgoing_interface host $source_ip and port $tested_dst_port -s0 -w" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi any host $source_ip and host $destination_ip and port $tested_dst_port -s0 -w" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_incoming_interface host $source_ip and port 8347 -s0 -w" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_outgoing_interface host $source_ip and port 8347 -s0 -w" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_outgoing_interface host $source_ip and port 8347 -s0 -w" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      conntrack -s $source_ip -E -o timestamp | awk -F "[\t]" '{ gsub(/(\[)/,"",$1) ;gsub(/(\])/,"",$1); print strftime("%c",$1) " " $2 }'" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      drppkt host $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tail -f /log/heartbeatd.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tail -f /log/access_server.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tail -f /log/hbtrust.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tail -f /log/awarrenhttp_access.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
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
echo "      cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_* | grep $affected_username" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_* | grep $affected_username >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- FOLLOWED KB ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  [Internal] GES MER - Sophos Firewall - Heartbeat  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008xYoQAI/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: Resolve Security Heartbeat registration problems  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008nHTQAY/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Central Wireless: Wireless clients missing heartbeat when behind a Sophos Firewall  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008wEOQAY/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Expiring Sophos Central Heartbeat Certificates  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z000000skjHQAQ/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

#### compress everything ####
tar -czvf /tmp/${case_number}_${xg_serial_number}_compressed.tar.gz /tmp/${case_number}_${xg_serial_number}/ > /dev/null 2>&1        #compress the folder to export

#### display the sap note ####
echo -en '\n'
echo -en '\n'
echo THIS IS THE SCRATCT SAP NOTE THAT HAS BEEN CREATED
echo -en '\n'
cat /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

#### sends logs to sophos ftp server ####
echo "RUN THE FOLLOWING COMMANDS TO SEND THE LOGS TO SOPHOS FTP SERVER"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_${xg_serial_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'

#### other logs to collect ####
echo "IN CASE YOU WOULD LIKE TO COLLECT A LOG DUMP FROM THE XG YOU CAN USE THIS COMMAND"
echo "      tar -czvf /tmp/logbundle_$(date +"%Y_%m_%d_%I_%M_%p").tar.gz /log/*.log"
echo -en '\n'
echo -en '\n'

#### missing logs ####
echo "CAN YOU PLEASE PROVIDE A SCREENSHOT FROM SOPHOS CENTRAL ABOUT THE HEARTHBEAT LICENSE?"
echo -en '\n'
echo -en '\n'
echo "CAN YOU PLEASE PROVIDE THE SDU FROM THE TESTED USER?"
echo -en '\n'
echo -en '\n'
