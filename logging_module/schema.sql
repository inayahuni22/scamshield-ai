-- Run this in the Supabase SQL editor before first use.
create table if not exists checks (
    id uuid primary key default gen_random_uuid(),
    created_at timestamptz default now(),
    input_type text not null,
    verdict text not null,
    explanation text,
    raw_signals jsonb
);
