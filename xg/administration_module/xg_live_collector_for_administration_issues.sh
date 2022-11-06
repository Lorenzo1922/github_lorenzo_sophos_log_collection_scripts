#!/bin/sh
####################################
#
#xg basic log collector for administration issues
#
####################################
#the esp packets are needed to understand why the vpn is not connecting

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
read -p "Which is the xg serial number? " xg_serial_number
read -p "What are you trying to achieve? " issue_description
read -p "Which is the sophos ftp username? " ftp_username
read -p "Which is the sophos ftp password? " ftp_password 
read -p "How many seconds you need to replicate the issue? " time_to_test

echo I am creating a folder named ${case_number}_${xg_serial_number}
mkdir /tmp/${case_number}_${xg_serial_number}

echo I am creating a report file with the commands used during the log collection named report_$case_number
touch /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo log collection event details >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo even details: >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
event_timestamp=$(date)
echo issue description is $issue_description >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo date during which I am collecting the logs = $event_timestamp >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

#### enable debug mode on modules ####
echo I am putting the following processes in debug mode

echo the csc service it put on debug
csc custom debug

#### log collection commands ####
tail -f /log/csc.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_csc_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_1_pid=$!

tail -f /log/applog.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_applog_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_2_pid=$!

tail -f /log/syslog.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_syslog_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_3_pid=$!

tail -f /log/garner.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_garner_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_4_pid=$!

tail -f /log/error_log.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_error_log_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_5_pid=$!

tail -f /log/postgres.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_postgres_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_6_pid=$!

tail -f /log/tomcat.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_tomcat_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

tail -f /log/confdbstatus.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_confdbstatus_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_8_pid=$!

tail -f /log/reportdb.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_reportdb_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_9_pid=$!

tail -f /log/u2d.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_u2d_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_10_pid=$!

tail -f /log/msync.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_msync_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_11_pid=$!

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

#### remove debug mode from modules ####
echo I am removing the debug mode from the following processes

echo the csc service it not on debug
csc custom debug

#### adding the used command in the report file ####
echo commands used during the log collection: >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 

echo tail -f /log/csc.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/applog.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/syslog.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/garner.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/error_log.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/postgres.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/tomcat.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/confdbstatus.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/reportdb.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/u2d.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo tail -f /log/msync.log >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

#file filtering / analysis
echo I am doing a bit of log analysis / filtering
echo I am creating a file with the strongswan log filtered by vpn name
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_csc_*.log | grep error >> /tmp/${case_number}_${xg_serial_number}/csc_filtered_by_word_error.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_csc_*.log | grep fail >> /tmp/${case_number}_${xg_serial_number}/csc_filtered_by_word_fail.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_applog_*.log | grep error >> /tmp/${case_number}_${xg_serial_number}/applog_filtered_by_word_error.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_applog_*.log | grep fail >> /tmp/${case_number}_${xg_serial_number}/applog_filtered_by_word_fail.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_syslog_*.log | grep error >> /tmp/${case_number}_${xg_serial_number}/syslog_filtered_by_word_error.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_syslog_*.log | grep fail >> /tmp/${case_number}_${xg_serial_number}/syslog_filtered_by_word_fail.txt

#### compress everything ####
tar -czvf /tmp/${case_number}_${xg_serial_number}_compressed.tar.gz /tmp/${case_number}_${xg_serial_number}/ > /dev/null 2>&1        #compress the folder to export

#### sends logs to sophos ftp server ####
echo "RUN THE FOLLOWING COMMANDS TO SEND THE LOGS TO SOPHOS FTP SERVER"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_${xg_serial_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'