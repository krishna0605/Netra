-- NETRA is server-mediated: browser clients use Supabase Auth, never the Data API.
-- Keep this migration paired with the Django default-deny and case-membership boundary.

begin;

-- Stop current browser roles from resolving the exposed public schema at all.
revoke usage on schema public from public, anon, authenticated;

-- Remove privileges and enable RLS as defense in depth on every Django-owned table.
do $netra_lockdown$
declare
    item record;
begin
    for item in
        select schemaname, tablename
        from pg_tables
        where schemaname = 'public'
          and (
              tablename like 'forensics\_%' escape '\'
              or tablename like 'auth\_%' escape '\'
              or tablename like 'django\_%' escape '\'
          )
    loop
        execute format('revoke all privileges on table %I.%I from anon, authenticated, service_role', item.schemaname, item.tablename);
        execute format('alter table %I.%I enable row level security', item.schemaname, item.tablename);
    end loop;
end
$netra_lockdown$;

-- Do not stream server-owned rows directly to browsers. The console polls the
-- authenticated Django API, which applies the same case boundary as all reads.
do $netra_realtime_lockdown$
declare
    item record;
begin
    for item in
        select schemaname, tablename
        from pg_publication_tables
        where pubname = 'supabase_realtime'
          and schemaname = 'public'
          and (
              tablename like 'forensics\_%' escape '\'
              or tablename like 'auth\_%' escape '\'
              or tablename like 'django\_%' escape '\'
          )
    loop
        execute format('alter publication supabase_realtime drop table %I.%I', item.schemaname, item.tablename);
    end loop;
end
$netra_realtime_lockdown$;

-- Opt this existing project into Supabase's 2026 explicit-exposure default.
alter default privileges for role postgres in schema public
    revoke select, insert, update, delete, truncate, references, trigger on tables from anon, authenticated, service_role;
alter default privileges for role postgres in schema public
    revoke usage, select, update on sequences from anon, authenticated, service_role;
alter default privileges for role postgres in schema public
    revoke execute on functions from anon, authenticated, service_role;
alter default privileges for role postgres in schema public
    revoke execute on functions from public;

commit;
