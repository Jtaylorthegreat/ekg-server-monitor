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

#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <mutex>    
#include <thread>
#include <ctime>
#include <vector>
#include <dirent.h>


#include "maind.h"

using namespace std;

mutex mtx;


void check_conf(){
    string agentconfig = ".agentconfig";
    ifstream fin(agentconfig.c_str());
        if(!fin) {
            cout << "Agent Failure - unable to read agent configuration file \n";
            exit(1);
        }
    fin.close();
    int numoflines = 0;
    string lines, path;
    ifstream countfile;
    path =".agentconfig";
    countfile.open(path);
    while (getline(countfile, lines))
        ++numoflines;
    countfile.close();
    ifstream file(".agentconfig");
    int line_counter = 0;

    int serveraddresscount = 0;
    int serverlisteningportcount = 0;
    int clientkeycount = 0;
    int agentlogcount = 0;
    int presharedkeycount = 0;
    int verifyingcertcount = 0;
    int checkagenttimercount = 0;

    string line, serveraddressoutput, serverlisteningportoutput, clientkeyoutput, agentlogoutput, presharedkeyoutput, verifyingcertoutput, checkagenttimeroutput;
    bool serveraddressok;
    bool serverlisteningportok;
    bool clientkeyok;
    bool agentlogok;
    bool presharedkeyok;
    bool verifyingcertok;
    bool checkagenttimerok;

    while (getline (file,line)) {
        line_counter++;
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());
            if(line[0] == '#' || line.empty())
                continue;
            if (line.find("serveraddress") != string::npos){
                serveraddresscount++;
            }
            if (line.find("serverlisteningport") != string::npos){
                serverlisteningportcount++;
            }
            if (line.find("clientkey") != string::npos){
                clientkeycount++;
            }
            if (line.find("agentlog") != string::npos){
                agentlogcount++;
            }
            if (line.find("presharedkey") != string::npos){
                presharedkeycount++;
            }
            if (line.find("verifyservercertificate") != string::npos){
                verifyingcertcount++;
            }
            if (line.find("agentcheckin") != string::npos){
                checkagenttimercount++;
            }
    }
    file.close();
    if (serveraddresscount < 1){
        serveraddressoutput = "serveraddress not found in conf file"; 
        serveraddressok = 0;
    }
    if (serveraddresscount > 1){
        serveraddressoutput = "Too many instances of serveraddress found in conf file";
        serveraddressok = 0;
     }
    if (serveraddresscount == 1){
        serveraddressoutput = "serveraddress ok";
        serveraddressok = 1;
    }
    //--------------------------------------------------------------------------------
    if (serverlisteningportcount < 1){
       serverlisteningportoutput = "serverlisteningport not found in conf file"; 
       serverlisteningportok = 0;
    }
    if (serverlisteningportcount > 1){
        serverlisteningportoutput = "Too many instances of serverlisteningport found in conf file";
        serverlisteningportok = 0;
    }
    if (serverlisteningportcount == 1){
        serverlisteningportoutput = "serverlisteningport ok";
        serverlisteningportok = 1;
    }
    //--------------------------------------------------------------------------------
    if (clientkeycount < 1){
       clientkeyoutput = "clientkey not found in conf file"; 
       clientkeyok = 0;
    }
    if (clientkeycount > 1){
        clientkeyoutput = "Too many instances of clientkey found in conf file";
        clientkeyok = 0;
    }
    if (clientkeycount == 1){
       clientkeyoutput = "clientkey ok";
        clientkeyok = 1;
    }
    //--------------------------------------------------------------------------------
    if (agentlogcount < 1){
       agentlogoutput = "agentlog not found in conf file"; 
       agentlogok = 0;
    }
    if (agentlogcount > 1){
        agentlogoutput = "Too many instances of agentlog found in conf file";
        agentlogok = 0;
    }
    if (agentlogcount == 1){
       agentlogoutput = "agentlog ok";
        agentlogok = 1;
    }
    //--------------------------------------------------------------------------------
    if (presharedkeycount < 1){
       presharedkeyoutput = "presharedkey not found in conf file"; 
       presharedkeyok = 0;
    }
    if (presharedkeycount > 1){
        presharedkeyoutput = "Too many instances of presharedkey found in conf file";
        presharedkeyok = 0;
    }
    if (presharedkeycount == 1){
       presharedkeyoutput = "presharedkey ok";
        presharedkeyok = 1;
    }
    //--------------------------------------------------------------------------------
    if (verifyingcertcount < 1){
       verifyingcertoutput = "verifyservercertificate not found in conf file"; 
       verifyingcertok = 0;
    }
    if (verifyingcertcount > 1){
        verifyingcertoutput = "Too many instances of verifyservercertificate found in conf file";
        verifyingcertok = 0;
    }
    if (verifyingcertcount == 1){
       verifyingcertoutput = "verifyservercertificate ok";
        verifyingcertok = 1;
    }
    //--------------------------------------------------------------------------------
    if (checkagenttimercount < 1){
       checkagenttimeroutput = "agentuploadqueue not found in conf file"; 
       checkagenttimerok = 0;
    }
    if (checkagenttimercount > 1){
        checkagenttimeroutput = "Too many instances of agentuploadqueue found in conf file";
        checkagenttimerok = 0;
    }
    if (checkagenttimercount == 1){
       checkagenttimeroutput = "agentuploadqueue ok";
        checkagenttimerok = 1;
    }
    //--------------------------------------------------------------------------------
    if (serveraddressok !=1 || serverlisteningportok !=1 || clientkeyok !=1 || agentlogok !=1 || presharedkeyok !=1 || verifyingcertok !=1 || checkagenttimerok !=1){
       cout << "Configuration file error: \n";
       if(serveraddressok == 0){
           cout << serveraddressoutput << "\n";
       }
       if(serverlisteningportok == 0){
           cout << serverlisteningportoutput << "\n";
       }
       if(clientkeyok == 0){
           cout << clientkeyoutput << "\n";
       }
       if(agentlogok == 0){
           cout << agentlogoutput << "\n";
       }
       if(presharedkeyok == 0){
           cout << presharedkeyoutput << "\n";
       }
       if(verifyingcertok == 0){
           cout << verifyingcertoutput << "\n";
       }
       if(checkagenttimerok == 0){
           cout << checkagenttimeroutput << "\n";
       }
       exit(1);
   }
}


void grab_config(ifstream& in, configfile& out){
    in.open(".agentconfig");
    string line;
    while(!in.eof()){
        while(getline(in,line)){
            line.erase(remove_if(line.begin(), line.end(), ::isspace),
                                    line.end());
                if(line[0] == '#' || line.empty())
                    continue;
            auto delimiterPos = line.find("=");
            string name;
            string debugg;
            name = line.substr(0, delimiterPos);
            if(name == "serverlisteningport")
                out.serverport = line.substr(delimiterPos +1);
            if(name == "serveraddress")
                out.serverip = line.substr(delimiterPos +1);
            if(name == "clientkey")
                out.clientkey = line.substr(delimiterPos +1);
            if(name == "debuglogging")
                out.debugg = line.substr(delimiterPos +1);
            if(name == "agentlog")
                out.agentlog = line.substr(delimiterPos +1);
            if(name == "presharedkey")
                out.presharedkey = line.substr(delimiterPos +1); 
            if(name == "verifyservercertificate")
                out.verifymycontroller = line.substr(delimiterPos +1);     
            if(name == "agentcheckin")
                out.clienttimer = line.substr(delimiterPos +1); 
        }
    }
}