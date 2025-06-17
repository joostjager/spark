-- Modify "token_mints" table
ALTER TABLE "token_mints" ADD COLUMN "token_identifier" bytea NULL;
-- Modify "token_outputs" table
ALTER TABLE "token_outputs" ADD COLUMN "token_identifier" bytea NULL;
-- Create index "tokenoutput_owner_public_key_token_identifier" to table: "token_outputs"
CREATE INDEX "tokenoutput_owner_public_key_token_identifier" ON "token_outputs" ("owner_public_key", "token_identifier");
-- Create "token_creates" table
CREATE TABLE "token_creates" ("id" uuid NOT NULL, "create_time" timestamptz NOT NULL, "update_time" timestamptz NOT NULL, "issuer_public_key" bytea NOT NULL, "wallet_provided_timestamp" bigint NULL, "issuer_signature" bytea NULL, "operator_specific_issuer_signature" bytea NULL, "creation_entity_public_key" bytea NOT NULL, "token_name" character varying NOT NULL, "token_ticker" character varying NOT NULL, "decimals" bigint NOT NULL, "max_supply" bytea NOT NULL, "is_freezable" boolean NOT NULL, "network" character varying NOT NULL, PRIMARY KEY ("id"));
-- Create index "token_creates_issuer_public_key_key" to table: "token_creates"
CREATE UNIQUE INDEX "token_creates_issuer_public_key_key" ON "token_creates" ("issuer_public_key");
-- Create index "token_creates_issuer_signature_key" to table: "token_creates"
CREATE UNIQUE INDEX "token_creates_issuer_signature_key" ON "token_creates" ("issuer_signature");
-- Create index "token_creates_operator_specific_issuer_signature_key" to table: "token_creates"
CREATE UNIQUE INDEX "token_creates_operator_specific_issuer_signature_key" ON "token_creates" ("operator_specific_issuer_signature");
-- Create index "tokencreate_issuer_public_key" to table: "token_creates"
CREATE UNIQUE INDEX "tokencreate_issuer_public_key" ON "token_creates" ("issuer_public_key");
-- Modify "token_transactions" table
ALTER TABLE "token_transactions" ADD COLUMN "token_transaction_create" uuid NULL, ADD CONSTRAINT "token_transactions_token_creates_create" FOREIGN KEY ("token_transaction_create") REFERENCES "token_creates" ("id") ON UPDATE NO ACTION ON DELETE SET NULL;
