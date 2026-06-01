# Local PostgreSQL Setup for Netra Phase 4

Phase 4 supports a clean local-first workflow where PostgreSQL runs natively on Windows and Netra containers connect to it through `host.docker.internal`. This lets you open pgAdmin and watch real Netra tables fill up as you create the first Admin, upload PCAP files, generate reports, confirm alerts, and export evidence.

No seeded users, cases, alerts, integrations, reports, or exports are created during normal startup.

## Official Downloads

- PostgreSQL Windows installer: https://www.postgresql.org/download/windows/
- PostgreSQL downloads: https://www.postgresql.org/download/?lang=en
- pgAdmin Windows download: https://www.pgadmin.org/download/pgadmin-4-windows/

The PostgreSQL Windows page points to the EDB interactive installer, which includes PostgreSQL Server, pgAdmin 4, and command-line tools.

## Install PostgreSQL on Windows

1. Open https://www.postgresql.org/download/windows/
2. Download the EDB interactive installer for Windows x86-64.
3. Use PostgreSQL 17 or 18. PostgreSQL 16 also works if it is already installed.
4. Run the installer as Administrator.
5. Select these components:
   - PostgreSQL Server
   - pgAdmin 4
   - Command Line Tools
6. Set a password for the `postgres` superuser. For a local demo only, `postgres` is easy to remember.
7. Use the installer-selected port. The usual default is:

```txt
5432
```

If another PostgreSQL instance or Docker container already occupied `5432`, the installer may choose another port such as `5434`. Netra's local PostgreSQL launcher auto-detects a running Windows PostgreSQL port.

8. Finish the installer and open pgAdmin.

## Create Netra Database and User

In pgAdmin, connect to the local server, open Query Tool, and run:

```sql
CREATE USER netra WITH PASSWORD 'netra';
CREATE DATABASE netra OWNER netra;
GRANT ALL PRIVILEGES ON DATABASE netra TO netra;
```

If you already created the user or database, use:

```sql
ALTER USER netra WITH PASSWORD 'netra';
GRANT ALL PRIVILEGES ON DATABASE netra TO netra;
```

## Test from PowerShell

If PostgreSQL Command Line Tools are on your PATH:

```powershell
psql -U netra -d netra -h localhost -p 5434
```

Then run:

```sql
SELECT current_database(), current_user;
```

Exit with:

```sql
\q
```

## Start Netra with Native PostgreSQL

From the project root:

```powershell
npm run netra:start:local-db
```

This starts frontend, backend, Elasticsearch, Kafka, workers, and storage in Docker, but uses Windows PostgreSQL for the database:

```txt
POSTGRES_HOST=host.docker.internal
POSTGRES_PORT=<auto-detected Windows PostgreSQL port>
POSTGRES_DB=netra
POSTGRES_USER=netra
POSTGRES_PASSWORD=netra
```

Open:

```txt
Frontend:        http://localhost:8080
Evidence intake:   http://localhost:8080/app/upload
Database status: http://localhost:8000/api/system/database
```

## First Netra Investigation

Netra has no seeded incidents and the current local workflow has no sign-in screen:

1. Open `http://localhost:8080/app/upload`.
2. Enter optional source, destination, protocol, port, duration, packet-limit, and capture-filter context.
3. Upload a real PCAP from `samples/pcaps`.
4. Open the dashboard and investigation pages.

Rows should now appear in PostgreSQL because of real evidence analysis.

## pgAdmin Connection

Create or open a pgAdmin server connection:

```txt
Host: localhost
Port: 5434
Maintenance database: netra
Username: netra
Password: netra
```

Look under:

```txt
Servers -> PostgreSQL -> Databases -> netra -> Schemas -> public -> Tables
```

## Tables to Inspect

Important forensic tables:

```txt
forensics_case
forensics_evidencefile
forensics_evidencemanifest
forensics_processingjob
forensics_alert
forensics_detectionmatch
forensics_anomalyrecord
forensics_sessionsummary
forensics_custodyledgerevent
forensics_accesslog
forensics_report
forensics_export
forensics_integrationconnection
forensics_integrationdelivery
forensics_sensor
forensics_capturejob
forensics_capturechunk
forensics_operationalevent
forensics_workerheartbeat
forensics_workerstagereceipt
```

Django auth and RBAC tables:

```txt
auth_user
forensics_userprofile
forensics_casemembership
```

## Useful SQL Checks

Before setup on a clean database:

```sql
SELECT COUNT(*) FROM auth_user;
SELECT COUNT(*) FROM forensics_case;
SELECT COUNT(*) FROM forensics_evidencefile;
SELECT COUNT(*) FROM forensics_alert;
```

Expected:

```txt
0 users
0 cases
0 evidence files
0 alerts
```

After first setup and one PCAP upload:

```sql
SELECT COUNT(*) FROM auth_user;
SELECT COUNT(*) FROM forensics_case;
SELECT COUNT(*) FROM forensics_evidencefile;
SELECT COUNT(*) FROM forensics_processingjob;
SELECT COUNT(*) FROM forensics_custodyledgerevent;
SELECT COUNT(*) FROM forensics_alert;
```

Expected:

```txt
auth_user >= 1
forensics_case >= 1
forensics_evidencefile >= 1
forensics_processingjob >= 1
forensics_custodyledgerevent >= 3
forensics_alert >= 1 for attack PCAPs such as hydra_ssh.pcap
```

## Validate

Run:

```powershell
npm run netra:validate:local-db
npm run netra:validate:phase4
```

`netra:validate:local-db` checks that Netra is connected to native PostgreSQL. `netra:validate:phase4` uploads a real PCAP through the no-login local workflow and verifies the resulting case, manifest, job, custody ledger, alerts, and database status.

## Docker PostgreSQL Is Still Available

For the all-Docker path:

```powershell
npm run netra:start
```

That uses Docker PostgreSQL. It is still useful for quick runs, but native PostgreSQL is better when you want pgAdmin visibility during a local hackathon demo.

## Resetting for a Clean Demo

Native PostgreSQL reset:

```sql
DROP DATABASE IF EXISTS netra;
DROP USER IF EXISTS netra;
CREATE USER netra WITH PASSWORD 'netra';
CREATE DATABASE netra OWNER netra;
GRANT ALL PRIVILEGES ON DATABASE netra TO netra;
```

Then run:

```powershell
npm run netra:start:local-db
```

Do this only when you intentionally want to delete local demo data.
