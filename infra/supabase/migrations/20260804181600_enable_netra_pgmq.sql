-- Netra uses PGMQ for its durable worker queues. Extension versions are
-- intentionally not pinned because Supabase manages available versions.
create extension if not exists pgmq;
