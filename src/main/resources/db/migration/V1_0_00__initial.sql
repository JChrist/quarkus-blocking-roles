-- This file allow to write SQL commands that will be emitted in test and dev.
-- The commands are commented as their support depends of the database
-- insert into myentity (id, field) values(1, 'field-1');
-- insert into myentity (id, field) values(2, 'field-2');
-- insert into myentity (id, field) values(3, 'field-3');
-- alter sequence myentity_seq restart with 4;

CREATE TABLE IF NOT EXISTS MyEntity (id BIGSERIAL NOT NULL PRIMARY KEY, field TEXT);
INSERT INTO MyEntity (id, field) VALUES (1, 'field-1'), (2, 'field-2'), (3, 'field-3') ON CONFLICT (id) DO NOTHING;
ALTER SEQUENCE MyEntity_id_seq RESTART WITH 4;