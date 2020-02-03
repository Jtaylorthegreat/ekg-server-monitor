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
#include <openssl/x509v3.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"

#include "maind.h"


using namespace std;

string IP, PORT, KEY, AGENTLOG, PSK, DEBUGVALUE, RFILEQUEUE, CONTRVERIFY, AUPLOADQUEUE, ACHECKINTIME;


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



int main()
{
    
    check_conf();
    ifstream openconf1;    
    configfile outp;
    grab_config(openconf1, outp);
    openconf1.close();



    IP = outp.serverip;
    PORT = outp.serverport;
    KEY = outp.clientkey;
    AGENTLOG = outp.agentlog;
    PSK = outp.presharedkey;
    const string CONSTUPLOADQUEUE = AUPLOADQUEUE;
    string debugging = outp.debugg;
    string verifyingmyc = outp.verifymycontroller;
    string getclienttimer = outp.clienttimer;
    


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

    if(verifyingmyc == "true" || verifyingmyc == "True" || verifyingmyc == "1"){
        CONTRVERIFY = "1";
    }
    else {
        CONTRVERIFY = "0";
    }
    if(getclienttimer == "5m" || getclienttimer == "5min"){
        ACHECKINTIME = "5m";
    }
    else if(getclienttimer == "15m" || getclienttimer == "15min"){
        ACHECKINTIME = "15m";
    }
    else {
        ACHECKINTIME = "30s";
    }

    spdlog::debug("------------------------------------------");
    spdlog::debug("ekg-agent daemon started");

    spdlog::debug("Configuration loaded with the following values:");
    spdlog::debug("MasterServerIP           = {}", IP.c_str());
    spdlog::debug("MasterServerPort         = {}", PORT.c_str());
    spdlog::debug("Agent key loaded         = {}", KEY.c_str());
    spdlog::debug("Agent log                = {}", AGENTLOG.c_str());
    spdlog::debug("PreSharedKey             = {}", PSK.c_str());
    spdlog::debug("VerifyServerCertificate  = {}", CONTRVERIFY.c_str());
    spdlog::debug("AgentChecking            = {}", ACHECKINTIME.c_str());



    char hostname[1024];
    gethostname(hostname, 1024);

    init_openssl();
    SSL_CTX *ctx;
    ctx = create_context();
    configure_context(ctx);

    while (true) { 
        SSL *ssl;
        int csocket = socket(AF_INET, SOCK_STREAM, 0);
        if (csocket == -1) {
            spdlog::critical(" Agent unable to obtain socket");
            return -1;
        }
        int servPORT = stoi(PORT);
        sockaddr_in tech;
        tech.sin_family = AF_INET;
        tech.sin_port = htons(servPORT);
        inet_pton(AF_INET, IP.c_str(), &tech.sin_addr);
        
        int conreq = connect(csocket, (sockaddr*)&tech, sizeof(tech));
        if (conreq < 0 ){
            spdlog::error("Unable to connect to server: {0} on port {1}", IP.c_str(), PORT.c_str());
        }
        else {
            X509 *givencert;
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, csocket);
            if (CONTRVERIFY == "1"){
                SSL_set_hostflags(ssl, X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS);
                SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
                if (!SSL_set1_host(ssl, IP.c_str())) {
                    /* handle and log error*/
                    spdlog::debug("Error setting server's hostname in verify ssl function");
                }
            }
            else {
                //this may be redundant since by default it doesn't verify the ssl now:
                SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
            }
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
                }
                else {
                    spdlog::error("Unsuccessful TLS/SSL handshake with server {}", IP.c_str());
                }
            }
            else {
                //X509 *givencert = NULL;
                givencert = SSL_get_peer_certificate(ssl);
                if (CONTRVERIFY == "1"){
                    if (givencert == NULL){
                        spdlog::error("Server Failed Certificate Verification - No Certificate presented");
                        SSL_free (ssl);
                        close(csocket);
                        X509_free(givencert);
                    }
                    else {
                        if(SSL_get_verify_result(ssl)!=X509_V_OK){
                            spdlog::error("Server Failed Certificate Verification");
                            SSL_free (ssl);
                            close(csocket);
                            X509_free(givencert);
                        }
                        else {
                            spdlog::debug("Server Certificate Verified");
                        }
                    }

                }
                
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
                    X509_free(givencert);
                }
                else {
                    //normal heartbeat call:
                    stringstream prefacekey;
                    prefacekey << ":--*" << hostname << "!heartbeat^" << KEY << "+";
                    const string sendkey = prefacekey.str();
                    const char *sendmessage = sendkey.c_str();
                                       
                           
                            SSL_write (ssl, sendmessage, strlen(sendmessage));
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
                                spdlog::error("#301 - Server unable to connect to database for client's heartbeat");
                                SSL_free (ssl);
                                close(csocket);
                                X509_free(givencert);
                            }
                            if (serverparsedcode == "hbderror2"){
                                spdlog::error("#302 - Server unable to process heartbeat request due to client hostname/key combination not being registered or enabled in database");
                                SSL_free (ssl);
                                close(csocket);
                                X509_free(givencert);
                            }
                            if (serverparsedcode == "hbsuccess"){
                                spdlog::info("Client heartbeat request successful");
                                SSL_free (ssl);
                                close(csocket);
                                X509_free(givencert);
                            }
                    } 
                }     
            }    
        
        
        if (ACHECKINTIME == "5m"){
            sleep(300);
        }
        else if (ACHECKINTIME == "15m"){
            sleep(900);
        }
        else {
            sleep(30);
        }
    }
    SSL_CTX_free (ctx);
    spdlog::info("agent shutdown gracefully");
    return 0;
}
