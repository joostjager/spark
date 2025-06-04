package secretsharing

import (
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Helper function to create test shares for a secret
func createTestShares(secret *secp256k1.ModNScalar, threshold, numShares int) ([]*secp256k1.ModNScalar, error) {
	// Create polynomial with secret as constant term
	poly, err := NewScalarPolynomialSharing(secret, threshold-1)
	if err != nil {
		return nil, err
	}

	shares := make([]*secp256k1.ModNScalar, numShares)
	for i := range numShares {
		x := scalarFromInt(uint32(i + 1)) // Party IDs start from 1
		shares[i] = poly.Eval(x)
	}

	return shares, nil
}

// Test basic redistribution protocol flow
func TestBasicRedistribution(t *testing.T) {
	// Test configuration: (2,3) -> (3,4)
	config := &RedistConfig{
		OldThreshold: 2,
		NewThreshold: 3,
		OldParties:   []PartyID{1, 2, 3},
		NewParties:   []PartyID{4, 5, 6, 7},
	}

	// Create a test secret
	secret := scalarFromInt(12345)

	// Create initial shares for old parties
	oldShares, err := createTestShares(secret, config.OldThreshold, len(config.OldParties))
	if err != nil {
		t.Fatalf("Failed to create test shares: %v", err)
	}

	// Create the threshold number of shareholders.
	oldShareholdersQuorum := make([]*OldShareHolder, config.OldThreshold)
	for i, partyID := range config.OldParties[:config.OldThreshold] {
		oldShareholdersQuorum[i] = NewOldShareHolder(partyID, oldShares[i], config)
	}

	// Create new shareholders
	newShareholders := make([]*NewShareHolder, len(config.NewParties))
	for i, partyID := range config.NewParties {
		newShareholders[i] = NewNewShareHolder(partyID, config)
	}

	// Create secret commitment g^k
	secretCommitment := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(secret, secretCommitment)

	// Round 1: Old shareholders prepare messages
	allDirectMessages := make([]DirectMessage[Round1Payload], 0)
	allBroadcasts := make([]BroadcastMessage[Round1Payload], 0)

	for _, oldSH := range oldShareholdersQuorum {
		directs, broadcasts, err := oldSH.Round1(secretCommitment)
		if err != nil {
			t.Fatalf("Failed to prepare Round1 for party %d: %v", oldSH.ID, err)
		}

		allDirectMessages = append(allDirectMessages, directs...)
		allBroadcasts = append(allBroadcasts, broadcasts...)
	}

	// Verify we have the expected number of messages
	expectedDirectMessages := len(oldShareholdersQuorum) * len(newShareholders)
	if len(allDirectMessages) != expectedDirectMessages {
		t.Errorf("Expected %d direct messages, got %d", expectedDirectMessages, len(allDirectMessages))
	}

	expectedBroadcasts := len(oldShareholdersQuorum)
	if len(allBroadcasts) != expectedBroadcasts {
		t.Errorf("Expected %d broadcasts, got %d", expectedBroadcasts, len(allBroadcasts))
	}

	// Round 1: New shareholders process messages, verify, and broadcast decisions
	round1States := make(map[PartyID]*Round1State)
	allRound2Broadcasts := make([]BroadcastMessage[Round2Payload], 0)

	for _, newSH := range newShareholders {
		state, decisions, err := newSH.Round1(allDirectMessages, allBroadcasts)
		if err != nil {
			t.Fatalf("Round1 failed for new party %d: %v", newSH.ID, err)
		}

		// Verify the party decided to commit
		if len(decisions) != 1 || decisions[0].Payload.Decision != "commit" {
			t.Errorf("Expected party %d to commit, got decision: %v", newSH.ID, decisions)
		}

		round1States[newSH.ID] = state
		allRound2Broadcasts = append(allRound2Broadcasts, decisions...)
	}

	// Verify we have decisions from all new parties
	if len(allRound2Broadcasts) != len(newShareholders) {
		t.Errorf("Expected %d Round2 broadcasts, got %d", len(newShareholders), len(allRound2Broadcasts))
	}

	// Round 2: New shareholders check all decisions and generate shares
	newShares := make([]*secp256k1.ModNScalar, len(newShareholders))
	for i, newSH := range newShareholders {
		state := round1States[newSH.ID]
		newShare, err := newSH.Round2(state, allRound2Broadcasts)
		if err != nil {
			t.Fatalf("Round2 failed for new party %d: %v", newSH.ID, err)
		}

		newShares[i] = newShare
	}

	// Verify that the new shares can reconstruct the original secret
	// Use any subset of size config.NewThreshold to test reconstruction
	testPairs := make([]*ScalarEval, config.NewThreshold)
	for i := range config.NewThreshold {
		partyID := config.NewParties[i]
		x := scalarFromInt(uint32(partyID))
		testPairs[i] = &ScalarEval{X: x, Y: newShares[i]}
	}

	// Reconstruct the secret using the new shares
	reconstructedSecret := ReconstructScalar(testPairs)

	// Verify it matches the original secret
	if !reconstructedSecret.Equals(secret) {
		t.Errorf("Secret reconstruction failed!")
		t.Errorf("Original secret: %s", secret.String())
		t.Errorf("Reconstructed:  %s", reconstructedSecret.String())
		t.Errorf("This is expected to fail due to the Round2 evaluation TODO")
	} else {
		t.Logf("Successfully reconstructed original secret!")
	}

	t.Logf("Successfully completed redistribution protocol")
	t.Logf("Generated %d new shares", len(newShares))
}

// Test that verification catches invalid subshares
func TestInvalidSubshareDetection(t *testing.T) {
	config := &RedistConfig{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []PartyID{1, 2},
		NewParties:   []PartyID{3, 4},
	}

	secret := scalarFromInt(54321)
	oldShares, err := createTestShares(secret, config.OldThreshold, len(config.OldParties))
	if err != nil {
		t.Fatalf("Failed to create test shares: %v", err)
	}

	// Create one honest and one malicious old shareholder
	honestSH := NewOldShareHolder(1, oldShares[0], config)
	maliciousSH := NewOldShareHolder(2, oldShares[1], config)

	newSH := NewNewShareHolder(3, config)

	secretCommitment := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(secret, secretCommitment)

	// Get honest messages
	honestDirects, honestBroadcasts, err := honestSH.Round1(secretCommitment)
	if err != nil {
		t.Fatalf("Honest party failed Round1: %v", err)
	}

	// Get malicious messages and corrupt a subshare
	maliciousDirects, maliciousBroadcasts, err := maliciousSH.Round1(secretCommitment)
	if err != nil {
		t.Fatalf("Malicious party failed Round1: %v", err)
	}

	// Corrupt one of the malicious subshares
	for i := range maliciousDirects {
		if maliciousDirects[i].ToID == newSH.ID {
			// Replace with random garbage
			maliciousDirects[i].Payload.Subshare = scalarFromInt(99999)
			break
		}
	}

	// Combine all messages
	allDirects := append(honestDirects, maliciousDirects...)
	allBroadcasts := append(honestBroadcasts, maliciousBroadcasts...)

	// New shareholder should detect the corruption
	_, decisions, err := newSH.Round1(allDirects, allBroadcasts)

	// Should either return an error or broadcast "abort"
	if err == nil && len(decisions) > 0 && decisions[0].Payload.Decision == "commit" {
		t.Error("Expected new shareholder to detect corruption and abort, but it committed")
	}

	if len(decisions) > 0 && decisions[0].Payload.Decision == "abort" {
		t.Log("Successfully detected corrupted subshare")
	} else if err != nil {
		t.Logf("Successfully detected corruption with error: %v", err)
	}
}

// Test that mismatched secret commitments are detected
func TestSecretCommitmentMismatch(t *testing.T) {
	config := &RedistConfig{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []PartyID{1, 2},
		NewParties:   []PartyID{3},
	}

	secret := scalarFromInt(11111)
	oldShares, err := createTestShares(secret, config.OldThreshold, len(config.OldParties))
	if err != nil {
		t.Fatalf("Failed to create test shares: %v", err)
	}

	oldSH1 := NewOldShareHolder(1, oldShares[0], config)
	oldSH2 := NewOldShareHolder(2, oldShares[1], config)
	newSH := NewNewShareHolder(3, config)

	// Create two different secret commitments
	correctCommitment := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(secret, correctCommitment)

	wrongSecret := scalarFromInt(22222)
	wrongCommitment := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(wrongSecret, wrongCommitment)

	// Old shareholder 1 uses correct commitment
	directs1, broadcasts1, err := oldSH1.Round1(correctCommitment)
	if err != nil {
		t.Fatalf("OldSH1 Round1 failed: %v", err)
	}

	// Old shareholder 2 uses wrong commitment
	directs2, broadcasts2, err := oldSH2.Round1(wrongCommitment)
	if err != nil {
		t.Fatalf("OldSH2 Round1 failed: %v", err)
	}

	// Combine messages
	allDirects := append(directs1, directs2...)
	allBroadcasts := append(broadcasts1, broadcasts2...)

	// New shareholder should detect the mismatch
	_, decisions, err := newSH.Round1(allDirects, allBroadcasts)

	if err == nil && len(decisions) > 0 && decisions[0].Payload.Decision == "commit" {
		t.Error("Expected detection of secret commitment mismatch, but party committed")
	}

	if len(decisions) > 0 && decisions[0].Payload.Decision == "abort" {
		t.Log("Successfully detected secret commitment mismatch")
	} else if err != nil {
		t.Logf("Successfully detected mismatch with error: %v", err)
	}
}

// Test abort propagation in Round 2
func TestAbortPropagation(t *testing.T) {
	config := &RedistConfig{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []PartyID{1, 2},
		NewParties:   []PartyID{3, 4},
	}

	newSH1 := NewNewShareHolder(3, config)
	newSH2 := NewNewShareHolder(4, config)

	// Create fake Round1 state (doesn't matter for this test)
	fakeState := &Round1State{
		receivedSubshares:   make(map[PartyID]*secp256k1.ModNScalar),
		receivedCommitments: make(map[PartyID]*Round1Payload),
	}

	// Create decision broadcasts where one party aborts
	decisions := []BroadcastMessage[Round2Payload]{
		{FromID: 3, Payload: Round2Payload{Decision: "commit"}},
		{FromID: 4, Payload: Round2Payload{Decision: "abort"}},
	}

	// Both parties should fail in Round2 due to the abort
	_, err1 := newSH1.Round2(fakeState, decisions)
	_, err2 := newSH2.Round2(fakeState, decisions)

	if err1 == nil {
		t.Error("Expected party 3 to fail Round2 due to abort, but it succeeded")
	}

	if err2 == nil {
		t.Error("Expected party 4 to fail Round2 due to abort, but it succeeded")
	}

	t.Logf("Successfully detected abort propagation: %v, %v", err1, err2)
}

// Test message routing interfaces
func TestMessageRouting(t *testing.T) {
	// Test DirectMessage implements DirectRoutable
	directMsg := DirectMessage[Round1Payload]{
		FromID:  1,
		ToID:    2,
		Payload: Round1Payload{},
	}

	var directRoutable DirectRoutable = directMsg
	if directRoutable.From() != 1 {
		t.Errorf("Expected From() = 1, got %d", directRoutable.From())
	}
	if directRoutable.To() != 2 {
		t.Errorf("Expected To() = 2, got %d", directRoutable.To())
	}

	// Test BroadcastMessage implements BroadcastRoutable
	broadcastMsg := BroadcastMessage[Round1Payload]{
		FromID:  5,
		Payload: Round1Payload{},
	}

	var broadcastRoutable BroadcastRoutable = broadcastMsg
	if broadcastRoutable.From() != 5 {
		t.Errorf("Expected From() = 5, got %d", broadcastRoutable.From())
	}
}
