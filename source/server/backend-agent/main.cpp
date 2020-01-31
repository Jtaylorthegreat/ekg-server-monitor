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
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <ctime>
#include <fstream>
#include <sstream>
#include <thread>
#include <sys/wait.h>
#include <algorithm>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "mysql_connection.h"
#include "mysql_driver.h"
#include "mysql_error.h"
#include <mysql.h>

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"
#define CIPHER_LIST "AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:AES128-SHA25"
#define CIPHER_LIST13 "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"


#include "funcsheet.h"


using namespace std;
using namespace sql;


  

string SPORT, DBserver, DBuser, DBuserPASS, DB, REGKEY, PSK, ENABLEREG, SERVLOG, SERVSSL, SERVSSLPRIVKEY, DEBUGVALUE, GLOBALAGENTTIMER;

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    }

    return ctx;
}

inline bool check_if_file_exists(const string& compfile) {
    struct stat compfilebuff;
    return (stat (compfile.c_str(), &compfilebuff) == 0);
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_cipher_list(ctx, CIPHER_LIST);
    SSL_CTX_set_ciphersuites(ctx, CIPHER_LIST13);
       
    
    if (SSL_CTX_use_certificate_file(ctx, SERVSSL.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVSSLPRIVKEY.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    }
} 


void hblisten (SSL* ssl, char* clientconnectedfromip){
    char buf[1024] = {0};
    int receivedclientcomms, sd;
    if (SSL_accept(ssl) <= 0) {
        if (DEBUGVALUE == "1"){
            FILE *sslerrs;
            spdlog::error("{} Unsuccessful client TLS/SSL handshake, connection dropped", clientconnectedfromip);
            spdlog::debug("[Openssl error]");
            spdlog::debug("---------------------------------------------------------");
            sslerrs=fopen(SERVLOG.c_str(), "a+");
            ERR_print_errors_fp(sslerrs);
            fclose(sslerrs);
            spdlog::debug("---------------------------------------------------------");
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1);
        }
        else {
            spdlog::error("{} Unsuccessful client TLS/SSL handshake, connection dropped", clientconnectedfromip);
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1);
        }
    }
    spdlog::debug("{} Accepted client TLS/SSL handshake, processing connection", clientconnectedfromip);
    //send psk to client for verification:
    stringstream prefacepsksend;
    prefacepsksend << ":" << PSK << "*";
    const string sendpsk = prefacepsksend.str();
    const char *sendpskmess = sendpsk.c_str();
    SSL_write (ssl, sendpskmess, strlen(sendpskmess));


    if ((receivedclientcomms = SSL_read(ssl, buf, sizeof(buf))) <= 0 ){
        spdlog::error("{} Connection dropped by agent", clientconnectedfromip);
        sd = SSL_get_fd (ssl);
        SSL_free(ssl);
        close (sd);
        exit(1);
    }
    buf[receivedclientcomms] = '\0';

    //keep below comment for enabling debug client message output in future:
    //spdlog::debug("Recieved client communication: {}", buf);

    string receivedclientmess = buf;
    size_t q = receivedclientmess.find(":");
    size_t p = receivedclientmess.find("*");
    size_t r = receivedclientmess.find("!");
    size_t s = receivedclientmess.find("^");
    size_t t = receivedclientmess.find("+");
    string clientparsedregkey = receivedclientmess.substr(q + 1, p - q - 1);
    string clientparsedhostname = receivedclientmess.substr(p + 1, r - p - 1);
    string clientparsedaction = receivedclientmess.substr(r + 1, s - r - 1);
    string clientparsedhbkey = receivedclientmess.substr(s + 1, t - s - 1);
    //string clientparsedcustomuploadfile = receivedclientmess.substr(t + 1);

    

    if (clientparsedaction == "heartbeat"){

        if (mysql_library_init(0, NULL, NULL)) {
            const char *hbdberror = ":hbdberror1*--!";
            SSL_write(ssl, hbdberror, strlen(hbdberror));
            spdlog::critical("Unable to connect to database for heart beat client check in");
            mysql_library_end();
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            delete(hbdberror);
            close (sd);
            exit(1);
        }
  
        sql::Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;
        try {
            driver = get_driver_instance();
            con = driver->connect(DBserver.c_str(), DBuser.c_str(), DBuserPASS.c_str());
            con->setSchema(DB.c_str());
            con-> setAutoCommit(0);
            stmt = con->createStatement();

            //match host query
            stringstream MH;
            MH << "SELECT * FROM clients WHERE ClientEnabled=true AND Clientkey='" << clientparsedhbkey << "' AND Hostname='" << clientparsedhostname << "'";
            string matchhostfromkey = MH.str();
    
            //set clientok bool to true
            stringstream CLO, CLO2;
            CLO << "UPDATE clients set ClientOK=true, ClientHB=CURRENT_TIMESTAMP WHERE ClientEnabled=true AND Clientkey='" << clientparsedhbkey << "' AND Hostname='" << clientparsedhostname << "'";
            string setclientokbool = CLO.str();
            CLO2 << "update clientinfo INNER JOIN clients on clientinfo.Hostname = clients.Hostname SET  clientinfo.ClientIP=INET_ATON('" << clientconnectedfromip << "') WHERE clients.ClientEnabled=true AND clients.Clientkey='" << clientparsedhbkey << "' AND clients.Hostname='" << clientparsedhostname << "'";
            string updateclientip = CLO2.str();
            stmt->execute(setclientokbool.c_str());
            stmt->execute("COMMIT;");
            stmt->execute(updateclientip.c_str());
            stmt->execute("COMMIT;");
            //execute query to match host to key, if key matches log heartbeat
            res = stmt->executeQuery(matchhostfromkey.c_str());
            //added if statement for when client key is not found in db
            if(res->next() == false){
                const char *hbderror2 = ":hbderror2*--!";
                spdlog::error("{2} Hostname: {0} using key: {1} failed heartbeat attempt due to host/key combination being unregistered or disabled", clientparsedhostname.c_str(), clientparsedhbkey.c_str(), clientconnectedfromip);
                SSL_write(ssl, hbderror2, strlen(hbderror2));
                delete res;
                delete stmt;
                delete con;
                mysql_library_end();
                sd = SSL_get_fd (ssl);
                SSL_free(ssl);
                delete(hbderror2);
                close (sd);
                exit(1);
            }
        delete res;
        delete stmt;
        delete con;
        }  catch (sql::SQLException &e) {
            spdlog::error("# ERR: {}", e.what());
            spdlog::error("Mysql error code: {}", e.what());
            spdlog::error("SQLState: {}", e.getSQLState());
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1);
            }
        mysql_library_end();
        sd = SSL_get_fd (ssl);
        SSL_free(ssl);
        close (sd);
        exit(0);
    }


    if (clientparsedaction == "register"){
        if (ENABLEREG == "true" || ENABLEREG == "True" || ENABLEREG == "1"){
        if (clientparsedregkey != REGKEY){
            const char *incregkey = ":regerror1*--!";
            SSL_write(ssl, incregkey, strlen(incregkey));
            spdlog::error("{} registration request denied due to incorrect registration key", clientconnectedfromip);
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1);
        }

        spdlog::info("{} registration key accepted for client register request", clientconnectedfromip);

        if (mysql_library_init(0, NULL, NULL)) {
            const char *regdbfail = ":regerror2*--!";
            SSL_write(ssl, regdbfail, strlen(regdbfail));
            spdlog::critical("Unable to connect to database for client registration");
            mysql_library_end();
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1);
        }
        try {
            sql::Driver *driver;
            sql::Connection *con;
            sql::Statement *stmt;
            sql::ResultSet *res;
            driver = get_driver_instance();
            con = driver->connect(DBserver.c_str(), DBuser.c_str(), DBuserPASS.c_str());
            con->setSchema(DB.c_str());
            con-> setAutoCommit(0);
            stmt = con->createStatement();

            //prevent duplicate hostname registrations
            stringstream chkdup;
            chkdup << "SELECT * FROM clients WHERE Hostname='" << clientparsedhostname << "'";
            string checkduplicates = chkdup.str();

            res = stmt->executeQuery(checkduplicates.c_str());
                if(res->next() == false ){
                    //built registration query for host
                    stringstream regaddformat, regaddformat2, regaddformat3, regaddformat4;
                    regaddformat << "INSERT INTO clients(Hostname, Clientkey, ClientOK, ClientEnabled, ClientHB, ClientRegDate) VALUES ('" << clientparsedhostname << "', uuid(), false, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";
                    string regclienttodb = regaddformat.str();
                    regaddformat2 << "INSERT INTO clientinfo(Hostname, ClientIP, OSVER) VALUES ('" << clientparsedhostname << "',(INET_ATON('" << clientconnectedfromip << "')), '" << clientparsedhbkey << "')";
                    string regclientinfotodb = regaddformat2.str();

                    stmt->execute("START TRANSACTION;");
                    stmt->execute(regclienttodb.c_str());
                    stmt->execute("COMMIT;");
                    stmt->execute(regclientinfotodb.c_str());
                    stmt->execute("COMMIT;");
                    
                    spdlog::info("{} successfully registered", clientparsedhostname.c_str());
                }
                else{
                    const char *duplicatehostname = ":regerror3*--!";
                    SSL_write(ssl, duplicatehostname, strlen(duplicatehostname));
                    spdlog::error("{1} Recieved duplicate registration request for hostname: {0}", clientparsedhostname.c_str(), clientconnectedfromip);
                    mysql_library_end();
                    sd = SSL_get_fd (ssl);
                    SSL_free(ssl);
                    close (sd);
                    exit(1);
                }
    
            delete res;
            res = stmt->executeQuery(checkduplicates.c_str());
                while (res->next()) {
                    string clientuniquekey = string(res->getString("Clientkey"));
                    stringstream clientkeymess;
                    clientkeymess << ":regsuccess*" << clientuniquekey << "!";
                    string clientkeyreply = clientkeymess.str();
                    SSL_write(ssl, clientkeyreply.c_str(), clientkeyreply.size());
                }
            delete res;
            delete stmt;
            delete con;
            }  catch (sql::SQLException &e) {
                spdlog::critical("# ERR: {}", e.what());
                spdlog::critical("Mysql error code: {}", e.what());
                spdlog::critical("SQLState: {}", e.getSQLState());
                mysql_library_end();
                sd = SSL_get_fd (ssl);
                SSL_free(ssl);
                close (sd);
                exit(1);
                }
        mysql_library_end();
        sd = SSL_get_fd (ssl);
        SSL_free(ssl);
        close (sd);
        exit(0);
        }
        else {
            const char *regdisabled = ":regdisabled*--!";
            SSL_write(ssl, regdisabled, strlen(regdisabled));
            spdlog::error("{} registration request denied due to registration request being disabled", clientconnectedfromip);
            mysql_library_end();
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1); 
        }

    }

    if (clientparsedaction == "enable"){
        if (ENABLEREG == "true" || ENABLEREG == "True" || ENABLEREG == "1"){

        if (clientparsedregkey != REGKEY){
            const char *incregkeyforen = ":enerror1*--!";
            SSL_write(ssl, incregkeyforen, strlen(incregkeyforen));
            spdlog::error("{} Client enable request denied due to incorrect registration key", clientconnectedfromip);
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1);
        }
        spdlog::info("{} registration key accepted for client enable request", clientconnectedfromip);
        if (mysql_library_init(0, NULL, NULL)) {
            const char *endbfail = ":enerror2*--!";
            SSL_write(ssl, endbfail, strlen(endbfail));
            spdlog::critical("{} Unable to connect to database for client's enable request", clientparsedhostname.c_str());
            mysql_library_end();
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1);
        }

        sql::Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;
        try {
            driver = get_driver_instance();
            con = driver->connect(DBserver.c_str(), DBuser.c_str(), DBuserPASS.c_str());
            con->setSchema(DB.c_str());
            con-> setAutoCommit(0);
            stmt = con->createStatement();
    
            stringstream locateclientindb;
            locateclientindb << "SELECT * FROM clients WHERE Clientkey='" << clientparsedhbkey << "'";
            string locateclient = locateclientindb.str();
    
            res = stmt->executeQuery(locateclient.c_str());
                if(res->next() == false ){
                    const char *endbfail = ":enerror3*--!";
                    SSL_write(ssl, endbfail, strlen(endbfail));
                    spdlog::error("{} Client enable request denied due to client being unregistered", clientparsedhostname.c_str());
                    mysql_library_end();
                    sd = SSL_get_fd (ssl);
                    SSL_free(ssl);
                    close (sd);
                    exit(1);
                }
                else {
                    delete res;
                    stringstream clientenformat;
                    clientenformat << "UPDATE clients set ClientEnabled=true WHERE Clientkey='" << clientparsedhbkey << "'";
                    string enclientremotely = clientenformat.str();

                    stmt->execute("START TRANSACTION;");
                    stmt->execute(enclientremotely.c_str());
                    stmt->execute("COMMIT;");
    
                    const char *ensuccess = ":ensuccess*--!";
                    SSL_write(ssl, ensuccess, strlen(ensuccess));
                    spdlog::info("{} agent remotely enabled", clientparsedhostname.c_str());
                }
            delete stmt;
            delete con;
             }  catch (sql::SQLException &e) {
                   spdlog::error("# ERR: {}", e.what());
                   spdlog::error("Mysql error code: {}", e.what());
                   spdlog::error("SQLState: {}", e.getSQLState());
                   mysql_library_end();
                   sd = SSL_get_fd (ssl);
                   SSL_free(ssl);
                   close (sd);
                   exit(1);
                }
        mysql_library_end();
        sd = SSL_get_fd (ssl);
        SSL_free(ssl);
        close (sd);
        exit(0);
        }
        else{
            const char *endisabled = ":endisabled*--!";
            SSL_write(ssl, endisabled, strlen(endisabled));
            spdlog::error("{} Client enable request denied due to registration being disabled", clientconnectedfromip);
            mysql_library_end();
            sd = SSL_get_fd (ssl);
            SSL_free(ssl);
            close (sd);
            exit(1); 
        }
    }

   

}


 
int main()
{
    
check_conf(); 

ifstream openconf1;    
configfile outp;
grab_config(openconf1,outp);
openconf1.close();


 
//Assign conf values from config file
SPORT = outp.serverport;
DBserver = outp.serverip;
DBuser = outp.sqluser;
DBuserPASS = outp.sqlpass;
DB = outp.database;
REGKEY = outp.agregkey;
PSK = outp.preserverkey;
ENABLEREG = outp.enableregistration;
string debugging = outp.debugg;
SERVLOG = outp.serverlog;
SERVSSL = outp.sslcertfile;
SERVSSLPRIVKEY = outp.sslkeyfile;
string getglobalagenttimer = outp.offlinetimer;

if(debugging == "true" || debugging == "True" || debugging == "1"){
    DEBUGVALUE = "1";
    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern("[%d/%b/%Y:%H:%M:%S] [thread %t] [PID %P] --%l %v");
    auto my_logger = spdlog::rotating_logger_mt("file_logger", SERVLOG.c_str(), 1048576 * 70, 7);
    spdlog::set_default_logger(my_logger);
    my_logger->flush_on(spdlog::level::debug);
}
else {
    DEBUGVALUE = "0";
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%d/%b/%Y:%H:%M:%S] --%l %v");
    auto my_logger = spdlog::rotating_logger_mt("file_logger", SERVLOG.c_str(), 1048576 * 70, 7);
    spdlog::set_default_logger(my_logger);
    my_logger->flush_on(spdlog::level::info);
}
if(getglobalagenttimer == "10m" || getglobalagenttimer == "10min"){
    GLOBALAGENTTIMER = "10m";
}
else if(getglobalagenttimer == "30m" || getglobalagenttimer == "30min"){
    GLOBALAGENTTIMER = "30m";
}
else {
    GLOBALAGENTTIMER = "5m";
}

spdlog::debug("------------------------------------------");
spdlog::debug("ekg-monitor server daemon started");
    

spdlog::debug("Configuration loaded with the following values:");
spdlog::debug("ServerListeningPort         = {}", SPORT.c_str());
spdlog::debug("ServerListeningAddress      = {}", DBserver.c_str());
spdlog::debug("Database User               = {}", DBuser.c_str());
spdlog::debug("Database Password           = {}", DBuserPASS.c_str());
spdlog::debug("Database                    = {}", DB.c_str());
spdlog::debug("AgentRegistrationKey        = {}", REGKEY.c_str());
spdlog::debug("PreSharedKey                = {}", PSK.c_str());
spdlog::debug("AcceptClientRegistrations   = {}", ENABLEREG.c_str());
spdlog::debug("AgentsMarkedOfflineAfter    = {}", GLOBALAGENTTIMER.c_str());


int PORT;
PORT = stoi(SPORT);

SSL_CTX *ctx;
init_openssl();
ctx = create_context();
configure_context(ctx);

int mysocket = socket(AF_INET, SOCK_STREAM, 0);
if (mysocket == -1) {
    spdlog::error("Server failed to create initial socket");
    return -1;
}

spdlog::debug("Initial socket creation successful");    
 
sockaddr_in tech;
tech.sin_family = AF_INET;
tech.sin_port = htons(PORT);
tech.sin_addr.s_addr = INADDR_ANY;
bind(mysocket, (sockaddr*)&tech, sizeof(tech));

spdlog::debug("Port {} successfully bound to socket", SPORT.c_str());    

int optval = 1;
socklen_t optlen = sizeof(optval);
setsockopt(mysocket, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen); 
    
listen(mysocket, SOMAXCONN);
 
sockaddr_in client;
socklen_t clientSize = sizeof(client);
int clientsocket, pid;

spdlog::debug("Server waiting for connections on port {}", SPORT.c_str());

thread t1(backend_processing);
t1.detach();

while (true) {


    SSL *ssl;
    clientsocket = accept(mysocket, (sockaddr*)&client, &clientSize);
    if (clientsocket < 0) {
        spdlog::error("Client error on socket accept");
        cerr << "Error on accept" << endl;
        return -1;
    }
    //added below to get client ip:
    char *clientconnectedfromip = inet_ntoa(client.sin_addr);
    
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientsocket);
    pid = fork ();
    if (pid < 0) {
        cerr << "error forking" << endl;
        spdlog::critical("Server failed to fork client connection");
        return -1;
    }
        
    if (pid == 0) {
        close(mysocket);
        hblisten(ssl, clientconnectedfromip);
        exit (0);
    }
    else {
        //added wait for defunct proccess cleanup
        wait(NULL);
        close(clientsocket);
        SSL_free(ssl);
    }

 
 }
 SSL_CTX_free(ctx);
 return 0;
}
