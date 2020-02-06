
# ekg-server-monitor
Simple agent based heartbeat monitor forked from  [RemoteCli](https://github.com/Jtaylorthegreat/RemoteCLI)
<br>
<br>

![screenshot2.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/screenshot2.jpg)


## **Server Installation Guide**

<br>

**Ubuntu 18.04:**

Install required packages:

	apt install php-mysql php mysql-server apache2 libmysqlcppconn-dev
	
Start/enable mysqld service and setup mysql-server:

	mysql_secure_installation
	systemctl enable mysql
Create user & database for ekg-monitor:
	
	mysql -u root -p 
	CREATE USER 'DBUSER'@'localhost' IDENTIFIED BY 'DATABASEPWHERE!'; 
	create database ENTERDATABASENAME; 
	grant all privileges on ENTERDATABASENAME.* to 'DBUSER'@'localhost'; 
	flush privileges;
Install ekg-monitor deb (enter database info when prompted):

	dpkg -i ekg-monitor-1.0.Ubuntu18.04-x86.deb
Update "agentregistrationkey" for ekg-monitor:	

	vi /opt/ekg-monitor/.serverconfig  

Enable & start ekg-monitor Service:

	systemctl enable ekg-monitor
	systemctl start ekg-monitor
Add Firewall Rules:

	ufw allow http
	ufw allow 60130/tcp


<hr>


<br><br>

## Agent Installation guide
<br>

**Ubuntu 18.04:**

Install ekg-agent deb:

	dpkg -i ekg-agent-1.0.Ubuntu18.04-x86.deb
Update "serveraddress" in agent configuration to reflect the appropriate monitor server:
	
	cd /opt/ekg-agent
	vi .agentconfig 
Register to the server using the server's configured registration key:

	./ekg-agent -r SERVERREGKEY
	./ekg-agent -e SERVERREGKEY
Enable & start the ekg-agent daemon:

	systemctl enable ekg-agentd
	systemctl start ekg-agentd
	

<br><br>

**Centos:**

Install ekg-agent rpm:
	
    Centos 8:
	  rpm -i ekg-agent-1.0-1.el8.x86_64.rpm
  
    Centos 7:
       rpm -i ekg-agent-1.0-1.el7.x86_64.rpm
	
	
Update "serveraddress" in agent configuration to reflect the appropriate ekg-monitor server:
	
	cd /opt/ekg-agent/
	vi .agentconfig 
Register to the ekg-monitor server using the server's configured registration key:

	./ekg-agent -r SERVERREGKEY
	./ekg-agent -e SERVERREGKEY
Enable & start the ekg-agentd daemon:

	systemctl enable ekg-agentd
	systemctl start ekg-agentd
<br><br>

**Windows:**

 1. Download
    [ekg-win-agent.rar](https://github.com/Jtaylorthegreat/ekg-server-monitor/blob/master/installers/ekg-win-agent.rar
    "ekg-win-agent.rar") and extract the files.
    
  
 2. Edit the .agentconfig Update "serveraddress" in agent configuration file to reflect the appropriate monitor server ![setup_win_1.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_1.jpg)![setup_win_2.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_2.jpg)
 3. Open command prompt, navigate to the extracted directory and register the agent by running the following appropriate commands:

        ekg-agent.exe -r AGENTREGISTRATIONKEY
        ekg-agent.exe -e AGENTREGISTRATIONKEY

 ![setup_win_3.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_3.jpg)
 

 4. After registration install the ekg-agentd service by running: 
 

        nssm install ekg-agentd
        
![setup_win_4.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_4.jpg)

 5. Select the appropriate application path to ekg-agentd.exe, set CPU usage as desired, and install service.
![setup_win_5.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_5.jpg)
![setup_win_6.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_6.jpg)

![setup_win_7.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_7.jpg)

 6. open services.msc from the windows menu, start ekg-agentd service, also verify in the service properties that the service startup type is set to automatic
![setup_win_8.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_8.jpg)
![setup_win_9.jpg](https://raw.githubusercontent.com/Jtaylorthegreat/ekg-server-monitor/master/screenshots/setup_win_9.jpg)

To **uninstall** the service, stop the ekg-agentd service, navigate to the extracted location and run the following:

    nssm remove ekg-agentd
