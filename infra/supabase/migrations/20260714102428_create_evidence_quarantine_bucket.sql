-- Browser clients may create one new quarantine object only under their own
-- immutable UUID prefix. No SELECT, UPDATE, or DELETE policy is granted.
begin;

insert into storage.buckets (id, name, public, file_size_limit)
values ('evidence-quarantine', 'evidence-quarantine', false, 524288000)
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit;

drop policy if exists "netra_insert_own_evidence_quarantine" on storage.objects;
create policy "netra_insert_own_evidence_quarantine"
on storage.objects
for insert
to authenticated
with check (
    bucket_id = 'evidence-quarantine'
    and (storage.foldername(name))[1] = (select auth.uid()::text)
    and name ~ ('^' || (select auth.uid()::text) || '/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/[^/]+$')
);

commit;
