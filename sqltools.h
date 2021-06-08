#include <stdio.h>
#include "sqlite3.h"
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

char* concat(int count, ...)
{
    va_list ap;
    int i;

    // Find required length to store merged string
    int len = 1; // room for NULL
    va_start(ap, count);
    for(i=0 ; i<count ; i++)
        len += strlen(va_arg(ap, char*));
    va_end(ap);

    // Allocate memory to concat strings
    char *merged = calloc(sizeof(char),len);
    int null_pos = 0;

    // Actually concatenate strings
    va_start(ap, count);
    for(i=0 ; i<count ; i++)
    {
        char *s = va_arg(ap, char*);
        strcpy(merged+null_pos, s);
        null_pos += strlen(s);
    }
    va_end(ap);

    return merged;
}

void put_packet_to_db(const char* buff, const char* device){
    char *err;
    sqlite3 *db;
    sqlite3_open("ip_stats.db", &db);
    int rc = sqlite3_exec(db, "create table if not exists statistics (Time DATETIME, Interface TEXT, SourceIP TEXT);",NULL, NULL, &err);
    if(rc != SQLITE_OK) printf("CREATE Error: %s ",err);
    
    char *query;
    query=concat(5, "INSERT INTO statistics VALUES (datetime(),'",device,"','",buff,"');");

    //printf("%s\n", query);
    rc = sqlite3_exec(db,query, NULL, NULL, &err);
    if(rc != SQLITE_OK) printf("EXEC Error: %s ",err);
    free(query);

    sqlite3_close(db);
}

void show_ip_count(const char* buff){

    char *err;
    sqlite3 *db;
    sqlite3_stmt* stmt;
    sqlite3_open("ip_stats.db", &db);

    char *query;
    query=concat(3, "SELECT Interface, SourceIP, Count(SourceIP) FROM statistics GROUP BY Interface, SourceIP HAVING (((SourceIP) Like '",buff,"'));");
    sqlite3_prepare_v2(db, query, -1, &stmt,0);
    unsigned int packet_count;
    const char *iface,*ip;
    while(sqlite3_step(stmt)!=SQLITE_DONE){
        iface = sqlite3_column_text(stmt,0);
        ip = sqlite3_column_text(stmt,1);
        packet_count = sqlite3_column_int(stmt,2);
        printf("Interface: %s | IP: %s | Incoming packets: %u\n",iface, ip, packet_count);
    }
    free(query);
    sqlite3_close(db);
}

void show_if_stat(const char* buff){

    char *err;
    sqlite3 *db;
    sqlite3_stmt* stmt;
    sqlite3_open("ip_stats.db", &db);

    char *query;
    query=concat(3, "SELECT Interface, Count(SourceIP) FROM statistics GROUP BY Interface HAVING (((Interface) Like '",buff,"'));");
    sqlite3_prepare_v2(db, query, -1, &stmt,0);
    unsigned int packet_count;
    const char *iface;
    while(sqlite3_step(stmt)!=SQLITE_DONE){
        iface = sqlite3_column_text(stmt,0);
        packet_count = sqlite3_column_int(stmt,1);
        printf("Interface: %s | Incoming packets: %u\n",iface, packet_count);
    }
    free(query);
    sqlite3_close(db);
}

void show_all_if_stat(){

    char *err;
    sqlite3 *db;
    sqlite3_stmt* stmt;
    sqlite3_open("ip_stats.db", &db);

    char *query;
    query=concat(1, "SELECT Interface, Count(SourceIP) FROM statistics GROUP BY Interface;");
    sqlite3_prepare_v2(db, query, -1, &stmt,0);
    unsigned int packet_count;
    const char *iface,*ip;
    while(sqlite3_step(stmt)!=SQLITE_DONE){
        iface = sqlite3_column_text(stmt,0);
        packet_count = sqlite3_column_int(stmt,1);
        printf("Interface: %s | Incoming packets: %u\n",iface, packet_count);
    }
    free(query);
    sqlite3_close(db);
}

void clear_db(){
    remove("ip_stats.db");
}