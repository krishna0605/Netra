-- Netra uses bounded authenticated Django SSE, not database Realtime.
begin;

do $netra_realtime_lockdown$
declare
    item record;
    remaining_count integer;
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
            execute format(
                'alter publication supabase_realtime drop table %I.%I',
                item.schemaname,
                item.tablename
            );
        end loop;

        select count(*)
          into remaining_count
          from pg_publication_tables
         where pubname = 'supabase_realtime'
           and schemaname = 'public'
           and (
               tablename like 'forensics\_%' escape '\'
               or tablename like 'auth\_%' escape '\'
               or tablename like 'django\_%' escape '\'
           );
        if remaining_count <> 0 then
            raise exception 'Expected zero Netra/Django Realtime members, found %', remaining_count;
        end if;
    end if;
end
$netra_realtime_lockdown$;

commit;
