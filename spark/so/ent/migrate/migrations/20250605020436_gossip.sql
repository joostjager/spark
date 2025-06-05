-- Create "gossips" table
CREATE TABLE "gossips" ("id" uuid NOT NULL, "create_time" timestamptz NOT NULL, "update_time" timestamptz NOT NULL, "participants" jsonb NOT NULL, "message" bytea NOT NULL, "receipts" bytea NOT NULL, "status" character varying NOT NULL DEFAULT 'PENDING', PRIMARY KEY ("id"));
-- Create index "gossip_status" to table: "gossips"
CREATE INDEX "gossip_status" ON "gossips" ("status");
