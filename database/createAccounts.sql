DROP TABLE IF EXISTS contacts;
CREATE TABLE contacts(
    id SERIAL,
    email TEXT,
    profile_picture TEXT,
    name_ TEXT,
    mobile_number TEXT,
    password TEXT
);

ALTER TABLE contacts ADD CONSTRAINT
CONTACTS_PRIMARY_KEY
    PRIMARY KEY(id)
;