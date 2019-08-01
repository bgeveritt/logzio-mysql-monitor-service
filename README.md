# logzio-mysql-monitor-service

#### Instructions (RHEL/CentOS 6):

* [Download] `logzio-db-monitor.sh` and `logzio-db-monitor`

* Place `logzio-db-monitor.sh` in `/usr/bin/`

* Edit the file, and update the necessary values (lines 319 - 322). Example:

  * `host=mysql.hostname`
  * `interval=60 #seconds`
  * `MYSQL_USER=my_username`
  * `MYSQL_PASS=my_password`
  
* Ensure the script is executable via `sudo chmod +x /usr/bin/logzio-db-monitor.sh`

* Place `logzio-db-monitor` in `/etc/init.d/`

* Ensure the script is executable via `sudo chmod +x /etc/init.d/logzio-db-monitor`

* Start/stop/restart/status via: `sudo /etc/init.d/logzio-db-monitor start|stop|restart|status`

#### Output:

* The service will execute the script based on the interval specified, and place the out to the following location:

  * `/var/log/logzio/logzio-mysql-monitor.log`
  * `/var/log/logzio/logzio-mysql-monitor-error.log`
  
[Download]: https://github.com/bgeveritt/logzio-mysql-monitor-service/releases/download/1.0/logzio-db-monitor.zip
