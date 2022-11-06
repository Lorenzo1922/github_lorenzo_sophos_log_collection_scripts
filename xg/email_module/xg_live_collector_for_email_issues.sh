#!/bin/sh
####################################
#
#xg basic log collector for email issues
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

	exit	
}

#### exit when customer finished to replicate the issue early ####
echo "PRESS CTRL + C IF YOU WANT TO STOP THE SCRIPT"
trap cleanup SIGINT 

#### what the script does ####
echo -en '\n'
echo "THIS SCRIPT WILL HELP YOU WITH EMAIL ISSUES"
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
read -p "Whis is sender email address? " sender_email_address
read -p "Whis is recipient email address? " recipient_email_address
read -p "Whis is recipient email subject? " email_subject
read -p "Whis is the direction of the email (incoming/outcoming)? " email_direction
read -p "Which is the protected domain by XG firewall? " xg_protected_domain
read -p "Which is the sender domain (so we can retrieve its sfp record)? " sender_domain
read -p "Whis is the mail server private ip? " mail_server_ip
read -p "Which is the sophos ftp username? " ftp_username
read -p "Which is the sophos ftp password? " ftp_password 
read -p "How many seconds you need to replicate the issue? " time_to_test

sleep 2
echo -en '\n'

xg_serial_number=$(nvram get  '#li.serial')
event_timestamp=$(date)
xg_interface_to_mail_server=$(ip -o route get ${mail_server_ip} | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
xg_outgoing_interface=$(ip -o route get 8.8.8.8 | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')

echo I am creating a folder that will contain all the logs we will collect named: ${case_number}_${xg_serial_number}
mkdir /tmp/${case_number}_${xg_serial_number}

echo I am creating a report file that will contained all the info about what we tested named: report_${case_number}_${xg_serial_number}
touch /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo -en '\n'

#check smtp status at the time of the event
echo "I AM CHECKING IF THE SMTPM SERVICE IS RUNNING"
echo "service -S | grep smtpd"
smtp_status=$(service -S | grep smtpd)

#### enable debug mode on modules ####
echo "I AM PUTTING THE FOLLOWING PROCESSES IN DEBUG MODE"
echo -en '\n'
echo SMTPD
service smtpd:debug -ds nosync     
service smtpd:exim_debug -ds nosync
smtp_module_status=$(service -S | grep smtpd)
echo the ips module status is:  $'\n'$smtp_module_status

#### check sender domain spf recorf ####
sender_sfp_record=$(nslookup -type=txt ${sender_domain})

#### log collection commands ####
echo -en '\n'
tcpdump -envvi $xg_interface_to_mail_server host $mail_server_ip -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_interface_to_mail_server_${xg_interface_to_mail_server}_and_mail_server_ip_${mail_server_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_1_pid=$! 

tcpdump -envvi $xg_outgoing_interface '(port 25 or port 587 or port 993 or port 143 or port 465 or port 26)' -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_outgoing_interface_${xg_outgoing_interface}_and_mail_ports_25_587_993_143_465_26_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_2_pid=$! 

conntrack -s $mail_server_ip -E -o timestamp | awk -F "[\t]" '{ gsub(/(\[)/,"",$1) ;gsub(/(\])/,"",$1); print strftime("%c",$1) " " $2 }' > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntract_filtering_by_mail_server_private_ip_${mail_server_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_3_pid=$!

tail -f /log/smtpd_main.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_smtp_main_logs_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_4_pid=$!

sleep $time_to_test             #wait enough time for someone to replicate the issue

#### kill running jobs in background ####
kill -9 $program_1_pid          
kill -9 $program_2_pid          
kill -9 $program_3_pid  
kill -9 $program_4_pid  

#### remove debug mode from modules ####
service smtpd:debug -ds nosync              #to remove debug mode from ips module
service smtpd:exim_debug -ds nosync         #to remove debug mode from ips module

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
echo "      protected domain by the XG = ${xg_protected_domain}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      mail server private ip = ${mail_server_ip}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- LOG COLLECTION EVENT DETAILS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      timestamp = $event_timestamp" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested sender email address = ${sender_email_address}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested recipient email address = ${recipient_email_address}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      email direction = ${email_direction}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      the xg reaches the email server with this interface = ${xg_interface_to_mail_server}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      email subject = ${email_subject}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- ASSESSMENT ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      What you think the real problem is" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- TROUBLESHOOTING STEPS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      replicated the issue collecting the logs" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check smtp status before collecting the logs"  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          ${smtp_status}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check sender domain spf record"  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          ${sender_sfp_record}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- COMMANDS USED DURING THE LOG COLLECTION ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_interface_to_mail_server host $mail_server_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_outgoing_interface 'and (port 25 or port 587 or port 993 or port 143 or port 465 or port 26)' -s0 -w" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      conntrack -s $mail_server_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/smtpd_main.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- COLLECTED LOG FILENAMES ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
search_dir=/tmp/${case_number}_${xg_serial_number}/
for file in $search_dir*;
do
  echo "    ${file##*/}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
done
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- LOG ANALYSIS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check smtp_main.log filtering by sender email address ${sender_email_address}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_smtp_main_logs_in_date_* | grep ${sender_email_address} >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check smtp_main.log filtering by recipient email address ${recipient_email_address}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_smtp_main_logs_in_date_* | grep ${recipient_email_address} >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- FOLLOWED KB ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  [Internal] GES MER - Sophos Firewall - Email Protection  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z000000gcVuQAI/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: Configure email protection in MTA mode  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008pWfQAI/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: Configure SPX encryption for email  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008pZuQAI/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: Set the email size scanning limit  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z000000XyWIQA0/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: Inbound emails not getting delivered through XG Email Legacy Mode " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008n9ZQAQ/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
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
echo "CAN YOU ATTACH THE AFFECTED EMAIL IN .EML OR .MSG INTO THE CASE?"
echo "TROUBLESHOOTING COMMANDS"
echo "      rm -f /sdisk/spool/output/db/retry*"
echo "      exim -qff"
echo "      service smtpd:restart -ds nosync"

#### other logs to collect ####
echo "IN CASE YOU WOULD LIKE TO COLLECT A LOG DUMP FROM THE XG YOU CAN USE THIS COMMAND"
echo "      tar -czvf /tmp/logbundle_$(date +"%Y_%m_%d_%I_%M_%p").tar.gz /log/*.log"
echo -en '\n'
echo -en '\n'