-- Reassert Netra's server-mediated access model after all Django tables exist.
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
    if application_table_count <> 49 then
        raise exception 'Expected 49 Netra/Django public tables, found %', application_table_count;
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
        execute format('revoke all privileges on table %I.%I from anon, authenticated, service_role', item.schemaname, item.tablename);
        execute format('alter table %I.%I enable row level security', item.schemaname, item.tablename);
    end loop;

    -- Netra has no browser-facing policies in public. Browser uploads are
    -- scoped through the separate storage.objects quarantine policy.
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
end
$netra_table_lockdown$;

do $netra_realtime_lockdown$
declare
    item record;
begin
    if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
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
    end if;
end
$netra_realtime_lockdown$;

alter default privileges for role postgres in schema public
    revoke select, insert, update, delete, truncate, references, trigger on tables from anon, authenticated, service_role;
alter default privileges for role postgres in schema public
    revoke usage, select, update on sequences from anon, authenticated, service_role;
alter default privileges for role postgres in schema public
    revoke execute on functions from anon, authenticated, service_role, public;

commit;
