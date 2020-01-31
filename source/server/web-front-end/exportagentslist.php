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

$all_agents_csv = mysqli_query($connection, "SELECT clients.Hostname, clients.ClientOK, clients.ClientEnabled, clients.ClientHB, clients.ClientRegDate, INET_NTOA(clientinfo.ClientIP), clientinfo.OSVER from clients join clientinfo on clients.Hostname = clientinfo.Hostname ORDER BY clients.Hostname ASC");

	if($num_of_registered_clients > 0){
        $outputfilename = "agentlist_" . date('Y-m-d') . ".csv";
        $delimiter = ",";
        $tempoutput = fopen('php://output', 'w');
        $fields = array('Hostname', 'Status', 'Enabled', 'Last check-in', 'Registration date', 'Reported IP', 'OSVER');
        fputcsv($tempoutput, $fields, $delimiter);
        while($csvrow = mysqli_fetch_array($all_agents_csv)){
            //Format for cleaner csv output:
            $AEnabled = ($csvrow['ClientEnabled'] == '1')?'Enabled':'Disabled';
            $AOK = ($csvrow['ClientOK'] == '1')?'Online':'Offline';
            if ($csvrow['OSVER'] == 'OS001'){$OS = 'Ubuntu 18.04';}
            if ($csvrow['OSVER'] == 'OS002'){$OS = 'Centos 7';}
            if ($csvrow['OSVER'] == 'OS003'){$OS = 'Centos 8';}
            if ($csvrow['OSVER'] == 'OS004'){$OS = 'Windows';}

            //-----End of csv format values----

            $agentdata = array($csvrow['Hostname'], $AOK, $AEnabled, $csvrow['ClientHB'], $csvrow['ClientRegDate'], $csvrow['INET_NTOA(clientinfo.ClientIP)'], $OS);
            fputcsv($tempoutput, $agentdata, $delimiter);
        }
        fseek($tempoutput, 0);
        header('Content-Type: text/csv');
        header('Content-Disposition: attachement; filename="' . $outputfilename . '";');
        fpassthru($tempoutput);

    }
    exit;

?>
