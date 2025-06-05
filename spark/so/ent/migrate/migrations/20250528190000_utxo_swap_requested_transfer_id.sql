-- Modify "utxo_swaps" table
ALTER TABLE "utxo_swaps" ADD COLUMN "requested_transfer_id" uuid;
