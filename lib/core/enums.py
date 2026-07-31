#!/usr/bin/env python3
"""
Shim cho lib.core.enums - sao lại NGUYÊN VĂN các enum mà tamper script sử dụng.

Các giá trị phải KHỚP CHÍNH XÁC với sqlmap gốc, vì một số tamper so sánh chuỗi DBMS
(vd `if kwargs.get("dbms") == DBMS.MYSQL`). Nguồn: sqlmap/lib/core/enums.py
"""


class PRIORITY(object):
    LOWEST = -100
    LOWER = -50
    LOW = -10
    NORMAL = 0
    HIGH = 10
    HIGHER = 50
    HIGHEST = 100


class HINT(object):
    PREPEND = 0
    APPEND = 1


class DBMS(object):
    ACCESS = "Microsoft Access"
    DB2 = "IBM DB2"
    FIREBIRD = "Firebird"
    MAXDB = "SAP MaxDB"
    MSSQL = "Microsoft SQL Server"
    MYSQL = "MySQL"
    ORACLE = "Oracle"
    PGSQL = "PostgreSQL"
    SQLITE = "SQLite"
    SYBASE = "Sybase"
    INFORMIX = "Informix"
    HSQLDB = "HSQLDB"
    H2 = "H2"
    MONETDB = "MonetDB"
    DERBY = "Apache Derby"
    VERTICA = "Vertica"
    MCKOI = "Mckoi"
    PRESTO = "Presto"
    ALTIBASE = "Altibase"
    MIMERSQL = "MimerSQL"
    CLICKHOUSE = "ClickHouse"
    CRATEDB = "CrateDB"
    CUBRID = "Cubrid"
    CACHE = "InterSystems Cache"
    EXTREMEDB = "eXtremeDB"
    FRONTBASE = "FrontBase"
    RAIMA = "Raima Database Manager"
    VIRTUOSO = "Virtuoso"
    SNOWFLAKE = "Snowflake"
    SPANNER = "Spanner"
    HANA = "SAP HANA"
