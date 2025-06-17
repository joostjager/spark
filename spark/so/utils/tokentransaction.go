package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	"github.com/lightsparkdev/spark/so/protoconverter"
)

// MaxTokenOutputs defines the maximum number of input or token outputs allowed in a token transaction.
const MaxInputOrOutputTokenTransactionOutputs = 500

// Zero represents a big.Int with value 0, used for amount comparisons.
var Zero = new(big.Int)

func HashTokenTransaction(tokenTransaction *tokenpb.TokenTransaction, partialHash bool) ([]byte, error) {
	if tokenTransaction == nil {
		return nil, fmt.Errorf("token transaction cannot be nil")
	}

	if tokenTransaction.Version == 0 {
		sparkTx, err := protoconverter.SparkTokenTransactionFromTokenProto(tokenTransaction)
		if err != nil {
			return nil, fmt.Errorf("failed to convert token transaction: %w", err)
		}
		return HashTokenTransactionV0(sparkTx, partialHash)
	}

	return nil, fmt.Errorf("unsupported token transaction version: %d", tokenTransaction.Version)
}

// hashTokenTransaction generates a SHA256 hash of the TokenTransaction by:
// 1. Taking SHA256 of each field individually
// 2. Concatenating all field hashes in order
// 3. Taking SHA256 of the concatenated hashes
// If partialHash is true generate a partial hash even if the provided transaction is final.
func HashTokenTransactionV0(tokenTransaction *pb.TokenTransaction, partialHash bool) ([]byte, error) {
	if tokenTransaction == nil {
		return nil, fmt.Errorf("token transaction cannot be nil")
	}

	h := sha256.New()
	var allHashes []byte

	// Hash input outputs if a transfer.
	if transferSource := tokenTransaction.GetTransferInput(); transferSource != nil {
		if transferSource.OutputsToSpend == nil {
			return nil, fmt.Errorf("transfer input outputs cannot be nil")
		}
		for i, output := range transferSource.GetOutputsToSpend() {
			if output == nil {
				return nil, fmt.Errorf("transfer input token output at index %d cannot be nil", i)
			}
			h.Reset()

			txHash := output.GetPrevTokenTransactionHash()
			if txHash != nil {
				if len(txHash) != 32 {
					return nil, fmt.Errorf("invalid previous transaction hash length at index %d: expected 32 bytes, got %d", i, len(txHash))
				}
				h.Write(txHash)
			}

			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, output.GetPrevTokenTransactionVout())
			h.Write(buf)
			allHashes = append(allHashes, h.Sum(nil)...)
		}
	}
	// Hash mint input if a mint
	if mintInput := tokenTransaction.GetMintInput(); mintInput != nil {
		h.Reset()
		pubKey := mintInput.GetIssuerPublicKey()
		if pubKey != nil {
			if len(pubKey) == 0 {
				return nil, fmt.Errorf("issuer public key cannot be empty")
			}
			h.Write(pubKey)
		}

		if mintInput.GetIssuerProvidedTimestamp() != 0 {
			nonceBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(nonceBytes, mintInput.GetIssuerProvidedTimestamp())
			h.Write(nonceBytes)
		}

		allHashes = append(allHashes, h.Sum(nil)...)
	}

	// Hash token outputs
	if tokenTransaction.TokenOutputs == nil {
		return nil, fmt.Errorf("token outputs cannot be nil")
	}
	for i, output := range tokenTransaction.TokenOutputs {
		if output == nil {
			return nil, fmt.Errorf("token output at index %d cannot be nil", i)
		}
		h.Reset()

		// Leaf ID is not set in the partial token transaction.
		if !partialHash && output.GetId() != "" {
			id := []byte(output.GetId())
			if len(id) == 0 {
				return nil, fmt.Errorf("token output ID at index %d cannot be empty", i)
			}
			h.Write(id)
		}

		ownerPubKey := output.GetOwnerPublicKey()
		if ownerPubKey != nil {
			if len(ownerPubKey) == 0 {
				return nil, fmt.Errorf("owner public key at index %d cannot be empty", i)
			}
			h.Write(ownerPubKey)
		}

		// Revocation public key is not set in the partial token transaction.
		if !partialHash {
			revPubKey := output.GetRevocationCommitment()
			if revPubKey != nil {
				if len(revPubKey) == 0 {
					return nil, fmt.Errorf("revocation public key at index %d cannot be empty", i)
				}
				h.Write(revPubKey)
			}

			withdrawalBondBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(withdrawalBondBytes, output.GetWithdrawBondSats())
			h.Write(withdrawalBondBytes)

			withdrawalLocktimeBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(withdrawalLocktimeBytes, output.GetWithdrawRelativeBlockLocktime())
			h.Write(withdrawalLocktimeBytes)
		}

		tokenPubKey := output.GetTokenPublicKey()
		if tokenPubKey != nil {
			if len(tokenPubKey) == 0 {
				return nil, fmt.Errorf("token public key at index %d cannot be empty", i)
			}
			h.Write(tokenPubKey)
		}

		tokenAmount := output.GetTokenAmount()
		if tokenAmount != nil {
			if len(tokenAmount) == 0 {
				return nil, fmt.Errorf("token amount at index %d cannot be empty", i)
			}
			if len(tokenAmount) > 16 {
				return nil, fmt.Errorf("token amount at index %d exceeds maximum length: got %d bytes, max 16", i, len(tokenAmount))
			}
			h.Write(tokenAmount)
		}

		allHashes = append(allHashes, h.Sum(nil)...)
	}

	operatorPublicKeys := tokenTransaction.GetSparkOperatorIdentityPublicKeys()
	if operatorPublicKeys == nil {
		return nil, fmt.Errorf("operator public keys cannot be nil")
	}

	// Sort operator keys for consistent hashing
	sort.Slice(operatorPublicKeys, func(i, j int) bool {
		return bytes.Compare(operatorPublicKeys[i], operatorPublicKeys[j]) < 0
	})

	// Hash spark operator identity public keys
	for i, pubKey := range operatorPublicKeys {
		if pubKey == nil {
			return nil, fmt.Errorf("operator public key at index %d cannot be nil", i)
		}
		if len(pubKey) == 0 {
			return nil, fmt.Errorf("operator public key at index %d cannot be empty", i)
		}
		h.Reset()
		h.Write(pubKey)
		allHashes = append(allHashes, h.Sum(nil)...)
	}

	// Hash the network field
	h.Reset()
	networkBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(networkBytes, uint32(tokenTransaction.GetNetwork()))
	h.Write(networkBytes)
	allHashes = append(allHashes, h.Sum(nil)...)

	// Final hash of all concatenated hashes
	h.Reset()
	h.Write(allHashes)
	return h.Sum(nil), nil
}

// HashOperatorSpecificTokenTransactionSignablePayload generates a hash of the operator-specific payload
// by concatenating hashes of the transaction hash and operator public key.
func HashOperatorSpecificTokenTransactionSignablePayload(payload *pb.OperatorSpecificTokenTransactionSignablePayload) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("operator specific token transaction signable payload cannot be nil")
	}

	h := sha256.New()
	var allHashes []byte

	// Hash final_token_transaction_hash
	h.Reset()
	txHash := payload.GetFinalTokenTransactionHash()
	if txHash != nil {
		if len(txHash) != 32 {
			return nil, fmt.Errorf("invalid final transaction hash length: expected 32 bytes, got %d", len(txHash))
		}
		h.Write(txHash)
	}
	allHashes = append(allHashes, h.Sum(nil)...)

	// Hash operator_identity_public_key
	h.Reset()
	pubKey := payload.GetOperatorIdentityPublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("operator identity public key cannot be nil")
	}
	if len(pubKey) == 0 {
		return nil, fmt.Errorf("operator identity public key cannot be empty")
	}
	h.Write(pubKey)
	allHashes = append(allHashes, h.Sum(nil)...)

	// Final hash of all concatenated hashes
	h.Reset()
	h.Write(allHashes)
	return h.Sum(nil), nil
}

// HashFreezeTokensPayload generates a hash of the freeze tokens payload by concatenating
// hashes of the owner public key, token public key, freeze status, timestamp and operator key.
func HashFreezeTokensPayload(payload *pb.FreezeTokensPayload) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("freeze tokens payload cannot be nil")
	}

	h := sha256.New()
	var allHashes []byte

	// Hash owner_public_key
	h.Reset()
	ownerPubKey := payload.GetOwnerPublicKey()
	if ownerPubKey == nil {
		return nil, fmt.Errorf("owner public key cannot be nil")
	}
	if len(ownerPubKey) == 0 {
		return nil, fmt.Errorf("owner public key cannot be empty")
	}
	h.Write(ownerPubKey)
	allHashes = append(allHashes, h.Sum(nil)...)

	// Hash token_public_key
	h.Reset()
	tokenPubKey := payload.GetTokenPublicKey()
	if tokenPubKey == nil {
		return nil, fmt.Errorf("token public key cannot be nil")
	}
	if len(tokenPubKey) == 0 {
		return nil, fmt.Errorf("token public key cannot be empty")
	}
	h.Write(tokenPubKey)
	allHashes = append(allHashes, h.Sum(nil)...)

	// Hash should_unfreeze
	h.Reset()
	if payload.GetShouldUnfreeze() {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	allHashes = append(allHashes, h.Sum(nil)...)

	// Hash issuer_provided_timestamp
	h.Reset()
	if payload.GetIssuerProvidedTimestamp() == 0 {
		return nil, fmt.Errorf("issuer provided timestamp cannot be 0")
	}
	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, payload.GetIssuerProvidedTimestamp())
	h.Write(nonceBytes)
	allHashes = append(allHashes, h.Sum(nil)...)

	// Hash operator_identity_public_key
	h.Reset()
	operatorPubKey := payload.GetOperatorIdentityPublicKey()
	if operatorPubKey == nil {
		return nil, fmt.Errorf("operator identity public key cannot be nil")
	}
	if len(operatorPubKey) == 0 {
		return nil, fmt.Errorf("operator identity public key cannot be empty")
	}
	h.Write(operatorPubKey)
	allHashes = append(allHashes, h.Sum(nil)...)

	// Final hash of all concatenated hashes
	h.Reset()
	h.Write(allHashes)
	return h.Sum(nil), nil
}

// TODO(token): Extend validation to handle the full token transaction after filling revocation keys.
// ValidatePartialTokenTransaction validates a token transaction request before revocation keys are assigned.
// It checks the transaction structure, signatures, and token amounts for both mint and transfer operations.
func ValidatePartialTokenTransaction(
	tokenTransaction *pb.TokenTransaction,
	tokenTransactionSignatures *pb.TokenTransactionSignatures,
	sparkOperatorsFromConfig map[string]*pb.SigningOperatorInfo,
	supportedNetworks []common.Network,
) error {
	if tokenTransaction == nil {
		return fmt.Errorf("token transaction cannot be nil")
	}
	if tokenTransaction.TokenOutputs == nil {
		return fmt.Errorf("outputs to create cannot be nil")
	}
	if len(tokenTransaction.TokenOutputs) == 0 {
		return fmt.Errorf("outputs to create cannot be empty")
	}
	if len(tokenTransaction.TokenOutputs) > MaxInputOrOutputTokenTransactionOutputs {
		return fmt.Errorf("too many token outputs, maximum is %d", MaxInputOrOutputTokenTransactionOutputs)
	}
	network, err := common.NetworkFromProtoNetwork(tokenTransaction.Network)
	if err != nil {
		return fmt.Errorf("failed to convert network: %w", err)
	}

	if !isNetworkSupported(network, supportedNetworks) {
		return fmt.Errorf("network %s is not supported", network)
	}

	// Validate all token outputs have the same token public key
	expectedTokenPubKey := tokenTransaction.TokenOutputs[0].GetTokenPublicKey()
	if expectedTokenPubKey == nil {
		return fmt.Errorf("token public key cannot be nil")
	}
	for _, output := range tokenTransaction.TokenOutputs {
		if output.GetTokenPublicKey() == nil {
			return fmt.Errorf("token public key cannot be nil")
		}
		if !bytes.Equal(output.GetTokenPublicKey(), expectedTokenPubKey) {
			return fmt.Errorf("all outputs must have the same token public key")
		}
	}

	// Validate that the transaction is either a mint or a transfer, but not both.
	hasMintInput := tokenTransaction.GetMintInput() != nil
	hasTransferInput := tokenTransaction.GetTransferInput() != nil
	if (!hasMintInput && !hasTransferInput) || (hasMintInput && hasTransferInput) {
		return fmt.Errorf("token transaction must have exactly one of issue_input or transfer_input")
	}

	// Validation for mint transactions.
	if mintInput := tokenTransaction.GetMintInput(); mintInput != nil {
		if mintInput.GetIssuerProvidedTimestamp() == 0 {
			return fmt.Errorf("issuer provided timestamp cannot be 0")
		}

		// Validate that the token public key on all created outputs
		// matches the issuer public key.
		if !bytes.Equal(mintInput.GetIssuerPublicKey(), expectedTokenPubKey) {
			return fmt.Errorf("token public key must match issuer public key for mint transactions")
		}

		// Validate that the transaction signatures match the issuer public key.
		if len(tokenTransactionSignatures.GetOwnerSignatures()) != 1 {
			return fmt.Errorf("mint transactions must have exactly one signature")
		}

		// Get the signature for the mint input.
		issueSignature := tokenTransactionSignatures.GetOwnerSignatures()[0]
		if issueSignature == nil {
			return fmt.Errorf("mint signature cannot be nil")
		}

		// Validate mint amounts > 0
		for i, output := range tokenTransaction.TokenOutputs {
			amount := new(big.Int).SetBytes(output.GetTokenAmount())

			if amount.Cmp(Zero) == 0 {
				return fmt.Errorf("mint amount for output %d cannot be 0", i)
			}
		}
	}

	// Validation for transfer transactions
	if transferSource := tokenTransaction.GetTransferInput(); transferSource != nil {
		if len(transferSource.GetOutputsToSpend()) == 0 {
			return fmt.Errorf("outputs to spend cannot be empty")
		}
		if len(tokenTransaction.GetTransferInput().OutputsToSpend) > MaxInputOrOutputTokenTransactionOutputs {
			return fmt.Errorf("too many outputs to spend, maximum is %d", MaxInputOrOutputTokenTransactionOutputs)
		}

		// Validate there is the correct number of signatures for outputs to spend.
		if len(tokenTransactionSignatures.GetOwnerSignatures()) != len(transferSource.GetOutputsToSpend()) {
			return fmt.Errorf("number of signatures must match number of outputs to spend")
		}
	}

	// Check that each operator's public key is present.
	for _, operatorInfoFromConfig := range sparkOperatorsFromConfig {
		found := false
		configPubKey := operatorInfoFromConfig.GetPublicKey()
		for _, pubKey := range tokenTransaction.GetSparkOperatorIdentityPublicKeys() {
			if bytes.Equal(pubKey, configPubKey) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing spark operator identity public key for operator %s", operatorInfoFromConfig.GetIdentifier())
		}
	}

	return nil
}

// ValidateOwnershipSignature validates the ownership signature of a token transaction and that it matches
// a predefined public key attached to the output being spent or the token being created and the submitted transaction.
// It supports both ECDSA DER signatures and Schnorr signatures.
func ValidateOwnershipSignature(ownershipSignature []byte, tokenTransactionHash []byte, ownerPublicKey []byte) error {
	if ownershipSignature == nil {
		return fmt.Errorf("ownership signature cannot be nil")
	}
	if tokenTransactionHash == nil {
		return fmt.Errorf("partial token transaction hash cannot be nil")
	}
	if ownerPublicKey == nil {
		return fmt.Errorf("owner public key cannot be nil")
	}

	// Check if it's a Schnorr signature (64 bytes fixed length) or try to parse as ECDSA DER
	if len(ownershipSignature) == 64 {
		// Try to parse as Schnorr signature
		schnorrSig, err := schnorr.ParseSignature(ownershipSignature)
		if err == nil {
			// It's a valid Schnorr signature
			pubKey, err := secp256k1.ParsePubKey(ownerPublicKey)
			if err != nil {
				return fmt.Errorf("failed to parse public key: %w", err)
			}
			if pubKey == nil {
				return fmt.Errorf("parsed public key is nil")
			}

			// Convert to btcec.PublicKey for Schnorr verification
			btcecPubKey := btcec.PublicKey(*pubKey)

			// Verify the Schnorr signature
			if !schnorrSig.Verify(tokenTransactionHash, &btcecPubKey) {
				return fmt.Errorf("invalid Schnorr signature")
			}

			return nil
		}
		// If Schnorr parsing failed, fall through to try DER parsing, which in rare cases could be 64 bytes.
	}

	// Try to parse as ECDSA DER signature
	sig, err := ecdsa.ParseDERSignature(ownershipSignature)
	if err != nil {
		return fmt.Errorf("failed to parse signature as either Schnorr or DER: %w", err)
	}
	if sig == nil {
		return fmt.Errorf("parsed signature is nil")
	}

	pubKey, err := secp256k1.ParsePubKey(ownerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	if pubKey == nil {
		return fmt.Errorf("parsed public key is nil")
	}

	if !sig.Verify(tokenTransactionHash, pubKey) {
		return fmt.Errorf("invalid ownership signature")
	}
	return nil
}

// ValidateRevocationKeys validates that the provided revocation private keys correspond to the expected public keys.
// It ensures the private keys can correctly derive the expected public keys, preventing key mismatches.
func ValidateRevocationKeys(revocationPrivateKeys []*secp256k1.PrivateKey, expectedRevocationPublicKeys [][]byte) error {
	if revocationPrivateKeys == nil {
		return fmt.Errorf("revocation private keys cannot be nil")
	}
	if expectedRevocationPublicKeys == nil {
		return fmt.Errorf("expected revocation public keys cannot be nil")
	}
	if len(expectedRevocationPublicKeys) != len(revocationPrivateKeys) {
		return fmt.Errorf("number of revocation private keys (%d) does not match number of expected public keys (%d)",
			len(revocationPrivateKeys), len(expectedRevocationPublicKeys))
	}

	for i, revocationKey := range revocationPrivateKeys {
		if revocationKey == nil {
			return fmt.Errorf("revocation private key at index %d cannot be nil", i)
		}

		if expectedRevocationPublicKeys[i] == nil {
			return fmt.Errorf("expected revocation public key at index %d cannot be nil", i)
		}

		revocationPubKey := revocationKey.PubKey()
		expectedRevocationPubKey, err := secp256k1.ParsePubKey(expectedRevocationPublicKeys[i])
		if err != nil {
			return fmt.Errorf("failed to parse expected revocation public key at index %d: %w", i, err)
		}
		if expectedRevocationPubKey == nil {
			return fmt.Errorf("parsed expected revocation public key is nil at index %d", i)
		}

		if !expectedRevocationPubKey.IsEqual(revocationPubKey) {
			return fmt.Errorf("revocation key mismatch at index %d: derived public key does not match expected", i)
		}
	}
	return nil
}

func isNetworkSupported(providedNetwork common.Network, networks []common.Network) bool {
	// UNSPECIFIED network should never be considered supported
	if providedNetwork == common.Unspecified {
		return false
	}

	supportedNetworkMap := make(map[common.Network]struct{})

	// Create a map for quick lookup of supported networks
	for _, n := range networks {
		supportedNetworkMap[n] = struct{}{}
	}
	// Check if the network is supported
	_, exists := supportedNetworkMap[providedNetwork]
	return exists
}
