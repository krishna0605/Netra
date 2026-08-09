-- Supersede the historical 49-table assertion after Django migrations
-- 0014 through 0017 have produced the reviewed 53-table application schema.
-- Netra is Django-mediated: browser Data API roles receive no application
-- table policy or privilege.
begin;

do $netra_expected_schema$
declare
    application_table_count integer;
begin
    select count(*)
      into application_table_count
      from information_schema.tables
     where table_schema = 'public'
       and table_type = 'BASE TABLE'
       and (
           table_name like 'forensics\_%' escape '\'
           or table_name like 'auth\_%' escape '\'
           or table_name like 'django\_%' escape '\'
       );

    if application_table_count <> 53 then
        raise exception 'Expected 53 Netra/Django public tables, found %', application_table_count;
    end if;
end
$netra_expected_schema$;

revoke usage on schema public from public, anon, authenticated;

do $netra_table_lockdown$
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
        execute format(
            'revoke all privileges on table %I.%I from public, anon, authenticated, service_role',
            item.schemaname,
            item.tablename
        );
        execute format('alter table %I.%I enable row level security', item.schemaname, item.tablename);
    end loop;

    for item in
        select schemaname, tablename, policyname
          from pg_policies
         where schemaname = 'public'
           and (
               tablename like 'forensics\_%' escape '\'
               or tablename like 'auth\_%' escape '\'
               or tablename like 'django\_%' escape '\'
           )
    loop
        execute format('drop policy %I on %I.%I', item.policyname, item.schemaname, item.tablename);
    end loop;

    for item in
        select sequence_schema as schemaname, sequence_name as sequencename
          from information_schema.sequences
         where sequence_schema = 'public'
           and (
               sequence_name like 'forensics\_%' escape '\'
               or sequence_name like 'auth\_%' escape '\'
               or sequence_name like 'django\_%' escape '\'
           )
    loop
        execute format(
            'revoke all privileges on sequence %I.%I from public, anon, authenticated, service_role',
            item.schemaname,
            item.sequencename
        );
    end loop;
end
$netra_table_lockdown$;

alter default privileges in schema public
    revoke all privileges on tables from public, anon, authenticated, service_role;
alter default privileges in schema public
    revoke all privileges on sequences from public, anon, authenticated, service_role;
alter default privileges in schema public
    revoke execute on functions from public, anon, authenticated, service_role;

do $netra_verify_lockdown$
declare
    rls_count integer;
    browser_policy_count integer;
    browser_privilege_count integer;
begin
    select count(*)
      into rls_count
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public'
       and c.relkind in ('r', 'p')
       and c.relrowsecurity
       and (
           c.relname like 'forensics\_%' escape '\'
           or c.relname like 'auth\_%' escape '\'
           or c.relname like 'django\_%' escape '\'
       );

    select count(*)
      into browser_policy_count
      from pg_policies
     where schemaname = 'public'
       and (
           tablename like 'forensics\_%' escape '\'
           or tablename like 'auth\_%' escape '\'
           or tablename like 'django\_%' escape '\'
       );

    select count(*)
      into browser_privilege_count
      from information_schema.table_privileges
     where table_schema = 'public'
       and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
       and (
           table_name like 'forensics\_%' escape '\'
           or table_name like 'auth\_%' escape '\'
           or table_name like 'django\_%' escape '\'
       );

    if rls_count <> 53 then
        raise exception 'Expected RLS on 53 Netra/Django tables, found %', rls_count;
    end if;
    if browser_policy_count <> 0 then
        raise exception 'Expected zero Netra/Django Data API policies, found %', browser_policy_count;
    end if;
    if browser_privilege_count <> 0 then
        raise exception 'Expected zero browser/service API table privileges, found %', browser_privilege_count;
    end if;
end
$netra_verify_lockdown$;

commit;
