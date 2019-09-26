-- sudo -u postgres createuser hacrs --encrypted --no-createdb --no-superuser --no-createrole --pwprompt
-- horseraddishsoup
-- sudo -u postgres createdb -O hacrs hacrs

-- as superuse: load crypto extension:
-- CREATE EXTENSION pgcrypto;

-- alter table if exists mturk_assoc drop constraint mturk_assoc_pkey;
-- alter table if exists tasklet_results_assoc drop constraint tasklet_results_assoc_pkey;

drop table if exists tasklet_session_log ;
drop table if exists mturk_assoc;
drop table if exists tasklet_results_assoc;
drop table if exists mturk_resources;
drop table if exists seed_tasklets;
drop table if exists drill_tasklets;
drop table if exists seek_tasklets;
drop table if exists tasklet_results;
drop table if exists tasklets;
drop table if exists mturk_tasklet_assignments;
drop table if exists programs;
drop table if exists coverage_cache;
drop type if exists tasklet_type;
drop type if exists users;
drop type if exists tasklet_status;
drop type if exists notes;



create type tasklet_type as enum ('SEED', 'SEEK', 'DRILL');

create type tasklet_status as enum ('WORKING', 'COMPLETE', 'ABORT');

create table programs (
    id                  BIGSERIAL        PRIMARY KEY,
    name                varchar(100),
    unique(name)
);

create table mturk_resources (
    id                  BIGSERIAL        PRIMARY KEY,
    hit_id              varchar(100),
    hit_gid             varchar(100)
);

create table tasklets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type                tasklet_type   not NULL,
    timestamp           TIMESTAMP WITH TIME ZONE NOT NULL default now(),
    program             integer references programs(id) ON UPDATE CASCADE ON DELETE CASCADE,
    amount              numeric,
    keywords            varchar(100),
    issued              boolean default false
);

create table mturk_assoc (
    mturk_ref           integer references mturk_resources(id) ON UPDATE CASCADE ON DELETE CASCADE,
    tasklet_ref         UUID references tasklets(id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT mturk_assoc_pkey PRIMARY KEY (mturk_ref, tasklet_ref)
);

create table mturk_tasklet_assignments (
    tasklet_ref         UUID references tasklets(id) ON UPDATE CASCADE ON DELETE CASCADE,
    worker_id           varchar(32),
    status              tasklet_status not NULL default 'WORKING',
    timestamp           TIMESTAMP WITH TIME ZONE NOT NULL default now(),
    CONSTRAINT mturk_tasklet_assignments_pkey PRIMARY KEY (tasklet_ref, worker_id)
);

create table tasklet_results (
    id                  BIGSERIAL        PRIMARY KEY,
    res                 varchar(100)
);

create table tasklet_results_assoc (
    result_ref          integer references tasklet_results(id) ON UPDATE CASCADE ON DELETE CASCADE,
    tasklet_ref         UUID references tasklets(id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT tasklet_results_assoc_pkey PRIMARY KEY (result_ref, tasklet_ref)
);


-- create table drill_tasklets (
--     id                  BIGSERIAL        PRIMARY KEY,
--     task_id             UUID references tasklets(id) ON UPDATE CASCADE ON DELETE CASCADE,
--     payout_arr          varchar(1024)
-- );


create table seed_tasklets (
    id                  BIGSERIAL        PRIMARY KEY,
    task_id             UUID references tasklets(id) ON UPDATE CASCADE ON DELETE CASCADE,
    bitmap              varchar(256),
    --mintransitinos      integer,
    payout_arr          varchar(1024)
);


-- create table seek_tasklets (
--     id                  BIGSERIAL        PRIMARY KEY,
--     task_id             UUID references tasklets(id) ON UPDATE CASCADE ON DELETE CASCADE,
--     --task_spec           varchar(1024),
--     outputfile varchar(1024)
-- );


create table tasklet_session_log (
    id                  BIGSERIAL        PRIMARY KEY,
    task_id             UUID references tasklets(id),
    hit_id              varchar(32),
    worker_id           varchar(32),
    assignment_id       varchar(32),
    execution_id        UUID,
    user_agent          varchar(300),
    remote_add          cidr
);

create table coverage_cache (
    id                  BIGSERIAL        PRIMARY KEY,
    timestamp           TIMESTAMP WITH TIME ZONE NOT NULL default now(),
    programs_coverage   varchar(4096)
);

create table users (
    id                  BIGSERIAL        PRIMARY KEY,
    name                varchar(100),
    permissions         varchar(100),
    utype               varchar(100),
    pwsalt              integer,
    pwhash              varchar(100),
    unique(name)
);

create table notes (
    id                  BIGSERIAL        PRIMARY KEY,
    user_id             integer references users(id) ON UPDATE CASCADE ON DELETE CASCADE,
    program_id           integer references programs(id) ON UPDATE CASCADE ON DELETE CASCADE,
    timestamp           TIMESTAMP WITH TIME ZONE NOT NULL default now(),
    text                varchar(10000)
);
