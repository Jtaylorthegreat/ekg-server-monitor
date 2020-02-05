/* Copyright 2020 Justin Taylor */

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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <sys/wait.h>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"

#include "main.h"


using namespace std;


string IP, PORT, KEY, AGENTLOG, PSK, DEBUGVALUE, RFILEQUEUE;

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
        if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

}

void init_openssl()
{ 
    SSL_load_error_strings();  
    ERR_load_crypto_strings(); 
    OpenSSL_add_all_algorithms();
    SSL_library_init();
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_help();
        return -1;
    }
    check_conf();
    ifstream openconf1;    
    configfile outp;
    grab_config(openconf1, outp);
    openconf1.close();

    string IP = outp.serverip;
    string PORT = outp.serverport;
    string KEY = outp.clientkey;
    AGENTLOG = outp.agentlog;
    PSK = outp.presharedkey;
    string debugging = outp.debugg;


    if(debugging == "true" || debugging == "True" || debugging == "1"){
        DEBUGVALUE = "1";
        spdlog::set_level(spdlog::level::debug);
        spdlog::set_pattern("[%d/%b/%Y:%H:%M:%S] [thread %t] [PID %P] --%l %v");
        auto my_logger = spdlog::rotating_logger_mt("file_logger", AGENTLOG.c_str(), 1048576 * 70, 7);
        spdlog::set_default_logger(my_logger);
        my_logger->flush_on(spdlog::level::debug);
    }
    else {
        DEBUGVALUE = "0";
        spdlog::set_level(spdlog::level::info);
        spdlog::set_pattern("[%d/%b/%Y:%H:%M:%S] --%l %v");
        auto my_logger = spdlog::rotating_logger_mt("file_logger", AGENTLOG.c_str(), 1048576 * 70, 7);
        spdlog::set_default_logger(my_logger);
        my_logger->flush_on(spdlog::level::info);
    }
    
    string suppliedparameter(argv[1]);

    if (suppliedparameter == "--register" || suppliedparameter == "-r"){
         if (argc != 3){
            cout << "Invalid amount of parameters supplied" << endl;
                        cout << "Usage: ./client --register REGISTRATIONKEY" << endl;
            return -1;
        } 
        char hostname[1024];
        gethostname(hostname, 1024);
        string REGKEY = argv[2];
        init_openssl();
        SSL_CTX *ctx;
        SSL *ssl;
        ctx = create_context();
        configure_context(ctx);


        int csocket = socket(AF_INET, SOCK_STREAM, 0);
        if (csocket == -1) {
            cerr << "Can't create socket! Exiting" << endl;
            return -1;
        }
        int servPORT = stoi(PORT);
        sockaddr_in tech;
        tech.sin_family = AF_INET;
        tech.sin_port = htons(servPORT);
        inet_pton(AF_INET, IP.c_str(), &tech.sin_addr);
        
        int conreq = connect(csocket, (sockaddr*)&tech, sizeof(tech));
        if (conreq < 0 ){
            cerr << "error connecting" << endl;
            return -1;
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, csocket);
        if (SSL_connect (ssl) <= 0){
            if (DEBUGVALUE == "1"){
                FILE *sslerrs;
                spdlog::error("Unsuccessful TLS/SSL handshake with server {}", IP.c_str());
                spdlog::debug("[Openssl error]");
                spdlog::debug("---------------------------------------------------------");
                sslerrs=fopen(AGENTLOG.c_str(), "a+");
                ERR_print_errors_fp (sslerrs);
                fclose(sslerrs);
                spdlog::debug("---------------------------------------------------------");
                return -1;
            }
            else {
                spdlog::error("Unsuccessful TLS/SSL handshake with server {}", IP.c_str());
                ERR_print_errors_fp (stderr);
                return -1;
            }
        }
        else {
            //Verification of server PSK:
            char pskbuf[1024] = {0};
            int recservpskcomms = SSL_read(ssl, pskbuf, sizeof(pskbuf));
            pskbuf[recservpskcomms] = '\0';
            string rawservpskcomms = pskbuf;
            size_t header = rawservpskcomms.find(":");
            size_t footer = rawservpskcomms.find("*");
            string serverparsedpsk = rawservpskcomms.substr(header + 1, footer - header - 1);
            if (serverparsedpsk != PSK){
                spdlog::error("Server {} failed preshared key check, connection dropped", IP.c_str());
                spdlog::debug("Server {0} using psk: {1} failed preshared key check, connection dropped", IP.c_str(), serverparsedpsk.c_str());
                SSL_free (ssl);
                close(csocket);
            }
            else {
                stringstream prefaceregkey;
                //default:
                //prefaceregkey << ":" << REGKEY << "*" << hostname << "!" << "register^--+";
                prefaceregkey << ":" << REGKEY << "*" << hostname << "!" << "register^OS001+";
                //prefaceregkey << ":" << REGKEY << "*" << hostname << "!" << "register^OS002+";
                //prefaceregkey << ":" << REGKEY << "*" << hostname << "!" << "register^OS003+";
                //prefaceregkey << ":" << REGKEY << "*" << hostname << "!" << "register^OS004+";
                const string prefaceregkeystring = prefaceregkey.str();
                const char *sendregkey = prefaceregkeystring.c_str();
                SSL_write (ssl, sendregkey, strlen(sendregkey));
                char buf[1024] = {0}; 
                int receivedservercomms;

                receivedservercomms = SSL_read(ssl, buf, sizeof(buf));
                buf[receivedservercomms] = '\0';

                string serverunparsedresponse = buf;
                size_t q = serverunparsedresponse.find(":");
                size_t p = serverunparsedresponse.find("*");
                size_t r = serverunparsedresponse.find("!");
                string serverparsedcode = serverunparsedresponse.substr(q + 1, p - q - 1);
                string serverparsedmess = serverunparsedresponse.substr(p + 1, r - p - 1);
            
                if (serverparsedcode == "regerror1"){
                    cout << "Error 101 - Unable to register agent due to incorrect server registration key" << "\n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "regerror2"){
                    cout << "Error 102 - Server failed to connect to database for client registration" << "\n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "regerror3"){
                    cout << "Error 103 - Failed to register client due to hostname being previously registered. " << "\n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "regdisabled"){
                    cout << "Error 104 - Failed to remotely register client due to remote registration requests being disabled \n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "regsuccess"){
                    string aagentconfig = ".agentconfig";
                    ifstream op(aagentconfig.c_str());
                        if(!op) {
                            cout << "Client successfully registered to server. Unable to load agent key to local configuration, please add agent key to your configuration: " << endl;
                            cout << serverparsedmess << endl;
                            SSL_free (ssl);
                            close(csocket);
                            exit(1);
                        }
                
                    //get count of lines in agentconfig
                    int numoflines = 0;
                    string lines;
                    ifstream countfile;
                    string path;
                    path = ".agentconfig";
                    countfile.open(path);
                    while (getline(countfile, lines))
                        ++numoflines;
                    countfile.close();
                
                    /*this whole section (includes delete_line function) was late night black magic session that just works (for now)
                    below section checks for all valid non comment "clientkey" entries in .agentconfig, removes them and appends the end of the 
                    .agentconfig file with recieved client unique key*/
                    //also this only works if client key is at the bottom of the file, weird things happen when it's not, need to go back and clean this up:
                    ifstream file(".agentconfig");
                    int line_counter = 0;
                    string line;
                    while (getline (file,line)) {
                        line_counter++;
                        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());
                            if(line[0] == '#' || line.empty())
                                continue;
                            //line_counter++;
                        if (line.find("clientkey") != string::npos) {
                            for (int i = 0; i < numoflines; i++){
                                delete_line(".agentconfig", line_counter);
                            }
                        }
                    } 
                    file.close();
                
                
                    string localconfig = ".agentconfig";    
                    ofstream appendingagentconfig;
                    appendingagentconfig.open(aagentconfig.c_str(), ios::out | ios::app);
                    appendingagentconfig << "\n";
                    appendingagentconfig << "clientkey = " << serverparsedmess << endl;
                    appendingagentconfig.close();
                
                    cout << "Client successfully registered to server" << "\n";
                    cout << "Client assigned key " << serverparsedmess << endl;
                    cout << "Client Key successfully added to local configuration" << "\n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(0);
                }
            }
        }
    }
        
    if (suppliedparameter == "--enable" || suppliedparameter == "-e"){
        if (argc != 3){
            cout << "Invalid amount of parameters supplied" << endl;
            cout << "Usage: ./client --enable REGISTRATIONKEY" << endl;
            return -1;
        }
        char hostname[1024];
        gethostname(hostname, 1024);
        int servPORT = stoi(PORT);
        string REGKEY = argv[2];
        init_openssl();
        SSL_CTX *ctx;
        SSL *ssl;
        ctx = create_context();
        configure_context(ctx);

        sockaddr_in tech;
        tech.sin_family = AF_INET;
        tech.sin_port = htons(servPORT);
        inet_pton(AF_INET, IP.c_str(), &tech.sin_addr);
        int csocket = socket(AF_INET, SOCK_STREAM, 0);
            if (csocket == -1) {
                cerr << "Can't create socket! Exiting" << endl;
                exit(1);
            }
        int conreq = connect(csocket, (sockaddr*)&tech, sizeof(tech));
            if (conreq < 0 ){
                cout << "error connecting to server on port " << PORT << endl;
                exit(1);
            } 
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, csocket);
        if (SSL_connect (ssl) <= 0){
            if (DEBUGVALUE == "1"){
                FILE *sslerrs;
                spdlog::error("Unsuccessful TLS/SSL handshake with server {}", IP.c_str());
                spdlog::debug("[Openssl error]");
                spdlog::debug("---------------------------------------------------------");
                sslerrs=fopen(AGENTLOG.c_str(), "a+");
                ERR_print_errors_fp (sslerrs);
                fclose(sslerrs);
                spdlog::debug("---------------------------------------------------------");
                return -1;
            }
            else {
                spdlog::error("Unsuccessful TLS/SSL handshake with server {}", IP.c_str());
                ERR_print_errors_fp (stderr);
                return -1;
            }
        }
        else {
            //Verification of server PSK:
            char pskbuf[1024] = {0};
            int recservpskcomms = SSL_read(ssl, pskbuf, sizeof(pskbuf));
            pskbuf[recservpskcomms] = '\0';
            string rawservpskcomms = pskbuf;
            size_t header = rawservpskcomms.find(":");
            size_t footer = rawservpskcomms.find("*");
            string serverparsedpsk = rawservpskcomms.substr(header + 1, footer - header - 1);
            if (serverparsedpsk != PSK){
                spdlog::error("Server {} failed preshared key check, connection dropped", IP.c_str());
                spdlog::debug("Server {0} using psk: {1} failed preshared key check, connection dropped", IP.c_str(), serverparsedpsk.c_str());
                SSL_free (ssl);
                close(csocket);
            }
            else {
                stringstream prefaceregkey;
                prefaceregkey << ":" << REGKEY << "*" << hostname << "!" << "enable^" <<  KEY  << "+";
                const string prefaceregkeystring = prefaceregkey.str();
                const char *sendregkey = prefaceregkeystring.c_str();
                SSL_write (ssl, sendregkey, strlen(sendregkey));

                char buf[1024] = {0}; 
                int receivedservercomms;
                receivedservercomms = SSL_read(ssl, buf, sizeof(buf));
                buf[receivedservercomms] = '\0';

                string serverunparsedresponse = buf;
                size_t q = serverunparsedresponse.find(":");
                size_t p = serverunparsedresponse.find("*");
                size_t r = serverunparsedresponse.find("!",r);
                string serverparsedcode = serverunparsedresponse.substr(q + 1, p - q - 1);
                string serverparsedmess = serverunparsedresponse.substr(p + 1, r - p - 1);
                if (serverparsedcode == "enerror1"){
                    cout << "Error 201 - Client enable request denied due to incorrect registration key" << "\n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "enerror2"){
                    cout << "Error 202 - Server unable to connect to database for client's enable request" << "\n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "enerror3"){
                    cout << "Error 203 - Client enable request denied due to client key being unregistered/not found in database, Please register client first before enabling" << "\n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "endisabled"){
                    cout << "Error 204 - Failed to remotely enable client due to remote registration requests being disabled \n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "ensuccess"){
                    cout << "Client successfully enabled \n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(0);
                }
            }
        }
    }
    if (suppliedparameter == "--heartbeat" || suppliedparameter == "-hb"){

        char hostname[1024];
        gethostname(hostname, 1024);
        init_openssl();
        SSL_CTX *ctx;
        SSL *ssl;
        ctx = create_context();
        configure_context(ctx);
        
        int csocket = socket(AF_INET, SOCK_STREAM, 0);
        if (csocket == -1) {
            cerr << "Can't create socket! Exiting" << endl;
            return -1;
        }
        
        
       int servPORT = stoi(PORT);
       sockaddr_in tech;
       tech.sin_family = AF_INET;
       tech.sin_port = htons(servPORT);
       inet_pton(AF_INET, IP.c_str(), &tech.sin_addr);
        
        int conreq = connect(csocket, (sockaddr*)&tech, sizeof(tech));
        if (conreq < 0 ){
            cout << "error connecting to server on port " << PORT << endl;
            return -1;
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, csocket);
        if (SSL_connect (ssl) <= 0){
            if (DEBUGVALUE == "1"){
                FILE *sslerrs;
                spdlog::error("Unsuccessful TLS/SSL handshake with server {}", IP.c_str());
                spdlog::debug("[Openssl error]");
                spdlog::debug("---------------------------------------------------------");
                sslerrs=fopen(AGENTLOG.c_str(), "a+");
                ERR_print_errors_fp (sslerrs);
                fclose(sslerrs);
                spdlog::debug("---------------------------------------------------------");
                return -1;
            }
            else {
                spdlog::error("Unsuccessful TLS/SSL handshake with server {}", IP.c_str());
                ERR_print_errors_fp (stderr);
                return -1;
            }
        }
        else {
            //Verification of server PSK:
            char pskbuf[1024] = {0};
            int recservpskcomms = SSL_read(ssl, pskbuf, sizeof(pskbuf));
            pskbuf[recservpskcomms] = '\0';
            string rawservpskcomms = pskbuf;
            size_t header = rawservpskcomms.find(":");
            size_t footer = rawservpskcomms.find("*");
            string serverparsedpsk = rawservpskcomms.substr(header + 1, footer - header - 1);
            if (serverparsedpsk != PSK){
                spdlog::error("Server {} failed preshared key check, connection dropped", IP.c_str());
                spdlog::debug("Server {0} using psk: {1} failed preshared key check, connection dropped", IP.c_str(), serverparsedpsk.c_str());
                SSL_free (ssl);
                close(csocket);
            }
            else {
                stringstream s2s;
                s2s << ":--*" << hostname << "!heartbeat^" << KEY << "+";
                const string formateds2s = s2s.str(); 
                const char *sendtoserver = formateds2s.c_str(); 
                SSL_write (ssl, sendtoserver, strlen(sendtoserver));     
                char buf[1024] = {0};
                int receivedservercomms;
                receivedservercomms = SSL_read(ssl, buf, sizeof(buf));
                buf[receivedservercomms] = '\0';
                string serverunparsedresponse = buf;
                size_t q = serverunparsedresponse.find(":");
                size_t p = serverunparsedresponse.find("*");
                size_t r = serverunparsedresponse.find("!");
                string serverparsedcode = serverunparsedresponse.substr(q + 1, p - q - 1);
                string serverparsedfilesize = serverunparsedresponse.substr(p + 1, r - p - 1);
                string serverparsedf = serverunparsedresponse.substr(r + 1);
                string serverparsedact = serverunparsedresponse.substr(p + 1);

                if (serverparsedcode == "hbdberror1"){
                    cout << "Error 301 - Server unable to connect to database for client's heartbeat \n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "hbderror2"){
                    cout << "Error 302 - Server unable to process heartbeat request due to client hostname/key combination not being registered or enabled in database \n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(1);
                }
                if (serverparsedcode == "hbsuccess"){
                    cout << "Client heartbeat request successful \n";
                    SSL_free (ssl);
                    close(csocket);
                    exit(0);
                }
            }
        }
    }

    if (suppliedparameter == "--help" || suppliedparameter == "-h"){
        print_help();
    }
    if (suppliedparameter == "--version" || suppliedparameter == "-v"){
        printf("Net-Agent Version " VERSION "\n");
        exit(0);
    }
    
    
return 0;
}
