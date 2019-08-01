#!/bin/bash

function set_up {

mkdir -p /var/log/logzio

}

# ---------------------------------------- 
# accept a command as an argument, on error
# exit with status code on error
# ---------------------------------------- 
function execute {
    #log "DEBUG" "Running command: $@"
    "$@" 2>> $ERROR_LOG_FILE
    local status=$?
    if [ $status -ne 0 ]; then
        log "ERROR" "Occurred while executing: $@"
        exit $status
    fi
}

function calc {
    awk "BEGIN { print "$*" }"
}

# ---------------------------------------- 
# produce a unique tmp file name
# ---------------------------------------- 
function unique_file_name() {
    local dirname=`dirname $0`
    local basename=`basename $0`
    local full=${dirname}/${basename}
    md5=`execute md5sum ${full} | awk '{ print $1 }'`
    basename=${full##*/}

    echo "/tmp/${md5}_${basename}.tmp"
}

# ---------------------------------------- 
# write log line to file 
# receive log message and log level (info by default)   
# ---------------------------------------- 
function print_to_file {
    local message=$1
    local host=$2
    local date=$(date -u +%s)
    echo "$date" "$host" "$message" >> $MONITOR_LOG_FILE
}

function clean_up {

    rm -f /tmp/*_logzio-mysql-monitor.sh.tmp
    rm -f /tmp/deadlocks_status.tmp

}

# ---------------------------------------- 
# Run check
# Connection_Failed_Attempts - Count the The total number of failed attempts to connect to MySQL 
# ---------------------------------------- 
function aborted_connects() {
    # Tmp file
    local tmp_file=`unique_file_name`

    mysql -N -h $host -u $MYSQL_USER -p${MYSQL_PASS} -e "SHOW GLOBAL STATUS LIKE 'aborted_connects';" > $tmp_file 2>> $ERROR_LOG_FILE
    
    if [ $? -ne 0 ]; then
        echo "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        return 1
    fi

    # The total number of failed attempts to connect to MySQL 
    local aborted_connects=$(cat $tmp_file | awk '{print $2}')
    print_to_file "Connection_Failed_Attempts: $aborted_connects" $host

}

# ---------------------------------------- 
# Run check
# Detected_Deadlock - Value of 1 will note the a deadlock has been detected
# ---------------------------------------- 
function detect_deadlock() {
    local tmp_file=/tmp/deadlocks_status.tmp

    mysql -Bse "SHOW ENGINE INNODB STATUS\G" -h $host -u $MYSQL_USER -p${MYSQL_PASS} | awk '/LATEST DETECTED DEADLOCK/{f=1} /WE ROLL BACK TRANSACTION /{f=0;print} f' > $tmp_file 2>> $ERROR_LOG_FILE

    if [ $? -ne 0 ]; then
        echo "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        return 1
    fi

    #Checking tmp file for any errors
    local valdump=`cat /tmp/deadlocks_status.tmp |wc -l`
    if [ $valdump = 0 ]; then
        print_to_file "Detected_Deadlock: 0" $host
    else
        local errors=$(cat /tmp/deadlocks_status.tmp)
        echo "$errors" > /tmp/current-deadlocks_status.tmp

        if [ -e "/tmp/prior-deadlocks_status.tmp" ]; then
	    echo "prior-deadlocks_status.tmp Exists" > /dev/null
        else
            touch /tmp/prior-deadlocks_status.tmp | echo "" > /tmp/prior-deadlocks_status.tmp
        fi

        local newentries=$(diff --suppress-common-lines -u /tmp/prior-deadlocks_status.tmp /tmp/current-deadlocks_status.tmp | grep '\+[0-9]')

        if [ "$newentries" == "" ] && [ "$errors" != "" ]; then
            print_to_file "Detected_Deadlock: 0" $host
        elif [ "$newentries" != "" ]; then
            echo "$errors" > /tmp/prior-deadlocks_status.tmp
            print_to_file "Detected_Deadlock: 1" $host
        fi
    fi
}

# ---------------------------------------- 
# Run check
# Percentage_Of_Full_Table_Scans - The percentage of full table running queries
# ---------------------------------------- 
function full_table_scans() {
    # Tmp file
    local tmp_file=`unique_file_name`

    mysql -h $host -u $MYSQL_USER -p${MYSQL_PASS} -e "SHOW GLOBAL STATUS LIKE 'Handler_read%'" > $tmp_file 2>> $ERROR_LOG_FILE

    if [ $? -ne 0 ]; then
        echo "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        return 1
    fi

    local handler_read_first=$(cat $tmp_file | grep Handler_read_first | xargs echo -n | awk '{print $2}')
    local handler_read_key=$(cat $tmp_file | grep Handler_read_key | xargs echo -n | awk '{print $2}')
    local handler_read_last=$(cat $tmp_file | grep Handler_read_last | xargs echo -n | awk '{print $2}')
    local handler_read_next=$(cat $tmp_file | grep Handler_read_next | xargs echo -n | awk '{print $2}')
    local handler_read_prev=$(cat $tmp_file | grep Handler_read_prev | xargs echo -n | awk '{print $2}')
    local handler_read_rnd=$(cat $tmp_file | grep Handler_read_rnd | xargs echo -n | awk '{print $2}')
    local handler_read_rnd_next=$(cat $tmp_file | grep Handler_read_rnd_next | xargs echo -n | awk '{print $2}')

    local prec=`calc "($handler_read_rnd_next+$handler_read_rnd)/($handler_read_rnd_next+$handler_read_rnd+$handler_read_first+$handler_read_next+$handler_read_key+$handler_read_prev)*100"`

    print_to_file "Percentage_Of_Full_Table_Scans: $prec" $host
}

# ---------------------------------------- 
# Run check
# Open_Users - Count the number the number of users that can be connected from anywere
# Root_User - Value of 1 indicat the a 'root' user exist
# Users_Missing_Password - Count the number of users without a password
# ---------------------------------------- 
function insecure_user() {
    # Tmp file
    local tmp_file=`unique_file_name`

    mysql -N -h $host -u $MYSQL_USER -p${MYSQL_PASS} -e "select host, user, authentication_string from mysql.user;" > $tmp_file 2>> $ERROR_LOG_FILE

    if [ $? -ne 0 ]; then
        echo "ERROR" "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        return 1
    fi

    # number the number of users that can be connected from anywere 
    local openusers=$(cat $tmp_file | awk '{print $1}' | grep ^%$ | wc -l)
    # print_to_file "Open_Users: $openusers" $host 

    # root user exist ?
    local rootuser=$(cat $tmp_file | awk '{print $2}' | grep ^root$ | wc -l)
    # print_to_file "Root_User: $rootuser" $host

    # number of users without a password
    local nopasswordusers=$(cat $tmp_file | awk '{print $3}' | grep ^$ | wc -l)
    # print_to_file "Users_Missing_Password: $nopasswordusers" $host

    print_to_file "Root_User: $rootuser Open_Users: $openusers Users_Missing_Password: $nopasswordusers" $host

}

# ---------------------------------------- 
# Run check
# Percentage_Of_Allowed_Connections - The percentage of currently used connections 
# ---------------------------------------- 
function max_allowed_connections() {
    # Tmp file
    local tmp_file=`unique_file_name`

    mysql -h $host -u $MYSQL_USER -p${MYSQL_PASS} -e "SHOW GLOBAL VARIABLES LIKE 'max_connections';" > $tmp_file 2>> $ERROR_LOG_FILE
    mysql -h $host -u $MYSQL_USER -p${MYSQL_PASS} -e "SHOW GLOBAL STATUS LIKE 'max_used_connections';" >> $tmp_file 2>> $ERROR_LOG_FILE

    if [ $? -ne 0 ]; then
        echo "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        return 1
    fi

    local max_connections=$(cat $tmp_file | grep -i max_connections | awk '{print $2}')
    local max_used_connections=$(cat $tmp_file | grep -i max_used_connections | awk '{print $2}')

    if [[ -z $max_used_connections ]]; then
        max_used_connections=0
    fi

    local div=$(execute echo $max_used_connections/$max_connections | bc -l)
    local prec=$(execute echo "$div * 100" | bc)

    print_to_file "Percentage_Of_Allowed_Connections: $prec" $host
}

# ---------------------------------------- 
# Run check
# Percentage_Of_Allowed_Connections - The percentage of currently used connections 
# ---------------------------------------- 
function read_write_ops() {
    # Tmp file
    local tmp_file=`unique_file_name`

    mysql -h $host -u $MYSQL_USER -p${MYSQL_PASS} -e "SHOW GLOBAL STATUS LIKE 'Key_reads';" > $tmp_file 2>> $ERROR_LOG_FILE
    
    if [ $? -ne 0 ]; then
        echo "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        return 1
    fi

    local key_reads=$(cat $tmp_file | grep -i Key_reads | awk '{print $2}')

    mysql -h $host -u $MYSQL_USER -p${MYSQL_PASS} -e "SHOW GLOBAL STATUS LIKE 'Key_writes';" > $tmp_file
    
    if [ $? -ne 0 ]; then
        echo "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        return 1
    fi

    local key_writes=$(cat $tmp_file | grep -i Key_writes | awk '{print $2}')

    print_to_file "Reads_Ops: $key_reads Write_Ops: $key_writes" $host

}

# ---------------------------------------- 
# Run check
# Slave_IO_Running - Whether the I/O thread for reading the master's binary log is running. Normally, you want this to be Yes unless you have not yet started replication or have explicitly stopped it with STOP SLAVE.
# Slave_SQL_Running - Whether the SQL thread for executing events in the relay log is running. As with the I/O thread, this should normally be Yes
# Seconds_Behind_Master - Whether the SQL thread for executing events in the relay log is running. As with the I/O thread, this should normally be Yes
# ---------------------------------------- 
function slave_status() {

    # Tmp file
    local tmp_file=`unique_file_name`

    mysql -h $host -u $MYSQL_USER -p${MYSQL_PASS} -e "show slave status;" > $tmp_file 2>> $ERROR_LOG_FILE

    if [ $? -ne 0 ]; then
        echo "ERROR" "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        return 1
    fi

    # check that master-slave replica is enabled or if we are running aginst to master server.
    local raw_count=$(cat $tmp_file | wc -l)
    local empty_set_raw_count=$(cat $tmp_file | grep "Empty set" | wc -l)

    if [[ $raw_count -eq 0 ]] || [[ $empty_set_raw_count -eq 1 ]]; then
        echo "ERROR" "Master-Slave Replica is not set or its the master server." >> $ERROR_LOG_FILE
        return 1
    fi

    local slave_io_running=$(cat $tmp_file | grep "Slave_IO_Running: Yes" | wc -l)
    #print_to_file "Slave_IO_Running: $slave_io_running" $host

    local slave_sql_running=$(cat $tmp_file | grep "Slave_SQL_Running: Yes" | wc -l)
    #print_to_file "Slave_SQL_Running: $slave_sql_running" $host

    local seconds_behind_master=$(cat $tmp_file | grep "Seconds_Behind_Master" | awk '{ print $2}')

    if [[ $seconds_behind_master =~ ^-?[0-9]+$ ]] ; then
        # print_to_file "Seconds_Behind_Master: $seconds_behind_master" $host
        print_to_file "Slave_IO_Running: $slave_io_running Slave_SQL_Running: $slave_sql_running Seconds_Behind_Master: $seconds_behind_master" $host
    else
        print_to_file "Slave_IO_Running: $slave_io_running Slave_SQL_Running: $slave_sql_running Seconds_Behind_Master: 0" $host
    fi
        
}

# ---------------------------------------- 
# Run check
# Uptime: The number of seconds the MySQL server has been running.
# Current_Active_Clients:The number of active threads (clients).
# Queries_Since_Startup: The number of questions (queries) from clients since the server was started.
# Slow_queries: The number of queries that have taken more than long_query_time seconds.
# Opens_Tables: The number of tables the server has opened.
# Flush_Tables: The number of flush, refresh, and reload commands the server has executed.
# Queries_per_second_avg: The number of tables that currently are open
# ---------------------------------------- 
function db_status() {

    # Tmp file
    local tmp_file=`unique_file_name`

    mysqladmin -h $host -u $MYSQL_USER -p${MYSQL_PASS} status > $tmp_file 2>> $ERROR_LOG_FILE


    if [ $? -ne 0 ]; then
        echo "Fail to run query. Please check connection to DB -h $host -u $MYSQL_USER -p****" >> $ERROR_LOG_FILE
        print_to_file "Uptime: 0" "$host"
        return 1
    fi

    status_uptime=$(cat $tmp_file | awk '{print $2}')
    status_active_clients=$(cat $tmp_file | awk '{print $4}')
    status_queries=$(cat $tmp_file | awk '{print $6}')
    status_slow_queries=$(cat $tmp_file | awk '{print $9}')
    status_opens_tables=$(cat $tmp_file | awk '{print $11}')
    status_flush_tables=$(cat $tmp_file | awk '{print $14}')
    status_current_open_tables=$(cat $tmp_file | awk '{print $17}')
    status_queries_per_second_avg=$(cat $tmp_file | awk '{print $22}')

    print_to_file "Uptime: $status_uptime Current_Active_Clients: $status_active_clients Queries_Since_Startup: $status_queries Slow_queries: $status_slow_queries Opens_Tables: $status_opens_tables Flush_Tables: $status_flush_tables Current_Open_Tables: $status_current_open_tables Queries_per_second_avg: $status_queries_per_second_avg" "$host"

}

host=
interval=
MYSQL_USER=
MYSQL_PASS=
MONITOR_LOG_FILE="/var/log/logzio/logzio-mysql-monitor.log"
ERROR_LOG_FILE="/var/log/logzio/logzio-mysql-monitor-error.log"

#Create Logz.io Log Directory
set_up

while true
 do
  #Execute Checks
  aborted_connects
  detect_deadlock
  full_table_scans
  insecure_user
  max_allowed_connections
  read_write_ops
  slave_status
  db_status
  clean_up
  sleep $interval
 done
