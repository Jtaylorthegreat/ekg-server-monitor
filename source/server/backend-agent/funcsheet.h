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
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <ctime>
#include <fstream>
#include <algorithm>



using namespace std;

struct configfile {
    string serverport;
    string serverip;
    string sqluser;
    string sqlpass;
    string database;
    string agregkey;
    string preserverkey;
    string enableregistration;
    string debugg;
    string serverlog;
    string sslcertfile;
    string sslkeyfile;
    string offlinetimer;
};
extern string SPORT, DBserver, DBuser, DBuserPASS, DB, REGKEY, PSK, ENABLEREG, SERVLOG, SERVSSL, SERVSSLPRIVKEY, DEBUGVALUE, GLOBALAGENTTIMER; 

const float kB = 1024;
const float MB = 1048576;
const float GB = 1073741824;

//funcdefs:
void backend_processing();
void grab_config(ifstream& in, configfile& out);
void check_conf();


//tlsinfo:
void init_openssl();
void cleanup_openssl();
