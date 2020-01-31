<?php
/* Copyright 2019 Justin Taylor */

   /*This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* Justin Taylor <taylor.justin199@gmail.com> */

session_start(); 
if(!isset($_SESSION['UserData']['Username'])){
  header("location:login.php");
  exit;
  }
require 'defs.php';
$HVALUE=$_REQUEST['rowId'];
$BUILDQUERY = "SELECT clients.Hostname, clients.ClientOK, clients.ClientEnabled, clients.ClientHB, clients.ClientRegDate, INET_NTOA(clientinfo.ClientIP), clientinfo.OSVER from clients join clientinfo on clients.Hostname = clientinfo.Hostname where clients.Hostname='$HVALUE'";
$query_agent_info = mysqli_query($connection, $BUILDQUERY);
echo "<link rel='stylesheet' type='text/css' href='stylesheet.css'/>";

echo "<head><meta http-equiv='content-type' content='text/html; charset=UTF-8'><link rel='shortcut icon' type='image/x-icon' href='favicon.ico' /><title>EKG Server Monitor</title></head>";
echo "<body><header id='header'> EKG Server Monitor </header>";
echo  "
    <div class='wrapper'>
      		<div class='tabs'>";

      	 //Tab 1:
        echo "<div class='tab'> <input name='css-tabs' id='tab-1'  class='tab-switch' type='radio'> <label for='tab-1' class='tab-label'><a href='overview.php'>Overview</label></a></div>";
        
        
        //Tab 2:
        echo "<div class='tab'> <input name='css-tabs' id='tab-2' checked='checked' class='tab-switch' type='radio'> <label for='tab-2' class='tab-label'><a href='agents.php'>Agents</a></label><div class='tab-content'>";
            

            while($row = mysqli_fetch_array($query_agent_info))
            {
                echo "<b><p>" . $row['Hostname'] . "</p></b>";
                echo "<hr>";
                if ($row['ClientEnabled'] == 1){
                    echo "<b> Agent: </b> Enabled  <br>";
                }
                else {
                    echo "<b> Agent: </b> Disabled <br>";
                }
                if ($row['ClientOK'] == 1){
                    echo "<b>Agent Status: </b><font color='green'> Online </font><br>";
                }
                else {
                    echo "<b>Agent Status: </b><font color='red'> Offline </font><br>";
                }
                echo "<b>Last Heartbeat: </b>" . $row['ClientHB'] . "<br>";
                echo "<b> Client Registered: </b>" . $row['ClientRegDate'] . "<br>";
                echo "<b> Reported IP: </b>" . $row['INET_NTOA(clientinfo.ClientIP)'] . "<br>";
                if ($row['OSVER'] == "OS001"){
                    echo "<b> Reported OS: </b> Ubuntu 18.04 <br>";
                }
                if ($row['OSVER'] == "OS002"){
                    echo "<b> Reported OS: </b> Centos 7 <br>";
                }
                if ($row['OSVER'] == "OS003"){
                    echo "<b> Reported OS: </b> Centos 8 <br>";
                }
                if ($row['OSVER'] == "OS004"){
                    echo "<b> Reported OS: </b> Windows <br>";
                }
                echo "<br><br>";
                if ($row['ClientEnabled'] == 1){
                    echo "<form method='post' ><button type='submit' name='disableagent' class='lynkme'>Click here to Disable agent </button></form>";
                    if(isset($_POST['disableagent'])) {
                        $build_disableagent = "UPDATE clients SET ClientEnabled='0' WHERE Hostname='$HVALUE'";
                        if (($disable_agent_update = mysqli_query($connection, $build_disableagent)) === TRUE ){
                            echo "Agent Disabled<br>";
                        } 
                        else {
                            echo "Error Disabling Agent<br>";
                        }

                    }
                }
                else {
                    echo "<form method='post' ><button type='submit' name='enableagent' class='lynkme'>Click here to Enable agent </button></form>";
                    if(isset($_POST['enableagent'])) {
                        $build_enableagent = "UPDATE clients SET ClientEnabled='1' WHERE Hostname='$HVALUE'";
                        if (($enable_agent_update = mysqli_query($connection, $build_enableagent)) === TRUE ){
                            echo "Agent Enabled<br>";
                        } 
                        else {
                            echo "Error Enabling Agent<br>";
                        }

                        
                    }
                }
                echo "<hr class='agent'>";
                echo "<br><br><br>";
                echo "<form method='post'>";
                echo "<input type ='checkbox' name = 'checkdeleteA'><font color='red'>Delete Agent </font>&nbsp";
                echo "<input type ='submit' name = 'deleteagent' value = 'Delete'></form>";
                echo "(This only removes the agent from the controller's database, please also be sure to stop, disable and uninstall the agent daemon.)";
                if(isset($_POST['deleteagent'])){
                    if(empty($_POST['checkdeleteA'])){
                        echo "Please check the box if you want to delete this agent";
                    }
                    else {
                        $build_delete_agent = "DELETE FROM clients, clientinfo USING clients join clientinfo on clients.Hostname = clientinfo.Hostname where clients.Hostname='$HVALUE'";
                        if(($delete_agent_from_db = mysqli_query($connection, $build_delete_agent)) === TRUE ) {
                            $successAredirect = $webredirectlocation . "agents.php";
                            header("location: $successAredirect");
                        }
                        else {
                            echo "Error deleting $HVALUE !<br>";
                        }
                    }
                }



                mysqli_close($connection);  
            }
            echo "</div>
            </div>";



        //Tab 3:
        echo "<div class='tab'> <input name='css-tabs' id='tab-3' class='tab-switch' type='radio'> <label for='tab-3' class='tab-label'><a href='logout.php'>Logout</a></label></div>";

echo "</div>
<div class='push'></div>
<div class ='footer-container'><footer class='footer'> . </footer></div></div>";


echo "</body>";
?>  
