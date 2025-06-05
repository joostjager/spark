-- Modify "utxo_swaps" table
ALTER TABLE "utxo_swaps" ADD COLUMN "spend_tx_signing_result" bytea NULL;
