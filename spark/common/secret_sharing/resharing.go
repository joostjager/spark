package secretsharing

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TODO: the spark operator has an index instead of a party ID.
// that index can't be used as a shareID directly because it starts at zero.
// some ideas for fixing that safely:
//   rename PartyID to ShareID and check that it's not zero
//   use function ShareIDFromPartyIndex to convert party ID before using it as a share ID

// PartyID represents a unique identifier for each party
type PartyID uint64

// Scalar wrapper for secp256k1 scalars
type Scalar = secp256k1.ModNScalar

// Point wrapper for secp256k1 curve points
type Point = secp256k1.JacobianPoint

// Protocol configuration
type RedistConfig struct {
	OldThreshold int       // m
	NewThreshold int       // m'
	OldParties   []PartyID // n parties
	NewParties   []PartyID // n' parties
}

// === Message Types ===

// DirectMessage is a point-to-point message directly between two parties
type DirectMessage[T any] struct {
	FromID  PartyID
	ToID    PartyID
	Payload T
}

// BroadcastMessage is a message that must be verifiably received identically by all parties
type BroadcastMessage[T any] struct {
	FromID  PartyID
	Payload T
}

type DirectRoutable interface {
	From() PartyID
	To() PartyID
}

type BroadcastRoutable interface {
	From() PartyID
}

func (m DirectMessage[T]) From() PartyID { return m.FromID }
func (m DirectMessage[T]) To() PartyID   { return m.ToID }

func (b BroadcastMessage[T]) From() PartyID { return b.FromID }

// === Payload Types ===

// Round 1 payload contains all data exchanged in Round 1
type Round1Payload struct {
	// For unicast messages
	Subshare *Scalar // ŝ_ij

	// For broadcast messages
	ShareCommitment  *Point   // g^s_i
	PolyCommitments  []*Point // g^a'_i1, ..., g^a'_i(m'-1)
	SecretCommitment *Point   // g^k
}

// Round 2 payload contains verification decisions from new parties
type Round2Payload struct {
	Decision string // "commit" or "abort"
}

// Round1State contains the results of Round 1 processing
type Round1State struct {
	receivedSubshares   map[PartyID]*Scalar
	receivedCommitments map[PartyID]*Round1Payload
}

// === Party Types ===

// OldShareHolder represents a party in the old access structure
type OldShareHolder struct {
	ID     PartyID
	Share  *Scalar // s_i
	Config *RedistConfig
}

// NewShareHolder represents a party in the new access structure
type NewShareHolder struct {
	ID     PartyID
	Config *RedistConfig
}

// === Protocol Implementation ===

// NewOldShareHolder creates a new old shareholder
func NewOldShareHolder(id PartyID, share *Scalar, config *RedistConfig) *OldShareHolder {
	return &OldShareHolder{
		ID:     id,
		Share:  share,
		Config: config,
	}
}

// NewNewShareHolder creates a new shareholder
func NewNewShareHolder(id PartyID, config *RedistConfig) *NewShareHolder {
	return &NewShareHolder{
		ID:     id,
		Config: config,
	}
}

// === Old Shareholder Methods ===

// Round1 - Old shareholder prepares subshares and commitments for new shareholders
func (o *OldShareHolder) Round1(secretCommitment *Point) ([]DirectMessage[Round1Payload], []BroadcastMessage[Round1Payload], error) {
	// Create polynomial that evaluates to s_i at x=0
	poly, err := NewScalarPolynomialSharing(o.Share, o.Config.NewThreshold-1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create polynomial: %w", err)
	}

	// Generate subshare messages for each new party
	directMessages := make([]DirectMessage[Round1Payload], 0, len(o.Config.NewParties))

	for _, newPartyID := range o.Config.NewParties {
		// Evaluate polynomial at j (treating PartyID as scalar)
		x := new(Scalar)
		x.SetInt(uint32(newPartyID))

		subshare := poly.Eval(x)

		directMessages = append(directMessages, DirectMessage[Round1Payload]{
			FromID: o.ID,
			ToID:   newPartyID,
			Payload: Round1Payload{
				Subshare: subshare,
			},
		})
	}

	// Create share commitment g^s_i and polynomial coefficient commitments g^a'_il
	commitmentPoly := poly.ToPointPolynomial()

	// Create broadcast message with commitments
	broadcastMessage := BroadcastMessage[Round1Payload]{
		FromID: o.ID,
		Payload: Round1Payload{
			ShareCommitment:  commitmentPoly.Coefs[0],
			PolyCommitments:  commitmentPoly.Coefs[1:],
			SecretCommitment: secretCommitment,
		},
	}

	return directMessages, []BroadcastMessage[Round1Payload]{broadcastMessage}, nil
}

// === New Shareholder Methods ===

// Round1 - New shareholder processes received subshares and commitments, verifies, and broadcasts decision
func (n *NewShareHolder) Round1(
	directMessages []DirectMessage[Round1Payload],
	broadcastMessages []BroadcastMessage[Round1Payload],
) (*Round1State, []BroadcastMessage[Round2Payload], error) {
	// Collect received data
	receivedSubshares := make(map[PartyID]*Scalar)
	receivedCommitments := make(map[PartyID]*Round1Payload)

	// Process direct messages (subshares)
	for _, msg := range directMessages {
		if msg.ToID != n.ID {
			continue // Skip messages not for us
		}
		if msg.Payload.Subshare != nil {
			receivedSubshares[msg.FromID] = msg.Payload.Subshare
		}
	}

	// Process broadcast messages (commitments)
	for _, broadcast := range broadcastMessages {
		receivedCommitments[broadcast.FromID] = &broadcast.Payload
	}

	// Determine decision based on verification
	decision := "commit"
	var verificationError error

	if len(receivedSubshares) == n.Config.OldThreshold {
		// Verify subshares against commitments using Feldman VSS
		for partyID, subshare := range receivedSubshares {
			commitment, exists := receivedCommitments[partyID]
			if !exists {
				decision = "abort"
				verificationError = fmt.Errorf("missing commitment from party %d", partyID)
				break
			}

			if err := n.verifySubshare(subshare, commitment); err != nil {
				decision = "abort"
				verificationError = fmt.Errorf("subshare verification failed for party %d: %w", partyID, err)
				break
			}
		}

		// Verify SHARES-VALID condition: g^k = prod_i (g^s_i)^b_i
		if decision == "commit" {
			if err := n.verifySharesValid(receivedCommitments); err != nil {
				decision = "abort"
				verificationError = fmt.Errorf("SHARES-VALID verification failed: %w", err)
			}
		}
	} else {
		decision = "abort"

		if len(receivedSubshares) < n.Config.OldThreshold {
			verificationError = fmt.Errorf("insufficient subshares: got %d, need %d",
				len(receivedSubshares), n.Config.OldThreshold)
		} else if len(receivedSubshares) > n.Config.OldThreshold {
			verificationError = fmt.Errorf("too many subshares: got %d, need %d",
				len(receivedSubshares), n.Config.OldThreshold)
		}
	}

	state := &Round1State{
		receivedSubshares:   receivedSubshares,
		receivedCommitments: receivedCommitments,
	}

	// Broadcast decision
	decisionBroadcast := BroadcastMessage[Round2Payload]{
		FromID: n.ID,
		Payload: Round2Payload{
			Decision: decision,
		},
	}

	// If we decided to abort, return the error for logging/debugging
	if decision == "abort" {
		return state, []BroadcastMessage[Round2Payload]{decisionBroadcast}, verificationError
	}

	return state, []BroadcastMessage[Round2Payload]{decisionBroadcast}, nil
}

// Round2 - New shareholder checks decisions from all parties and generates share if all committed
func (n *NewShareHolder) Round2(state *Round1State, decisions []BroadcastMessage[Round2Payload]) (*Scalar, error) {
	// Check that we have decisions from all new parties
	expectedParties := len(n.Config.NewParties)
	if len(decisions) < expectedParties {
		return nil, fmt.Errorf("insufficient decisions: got %d, expected %d", len(decisions), expectedParties)
	}

	// Verify all parties committed
	for _, decision := range decisions {
		if decision.Payload.Decision != "commit" {
			return nil, fmt.Errorf("party %d aborted, protocol failed", decision.FromID)
		}
	}

	pairs := make([]*ScalarEval, 0, n.Config.OldThreshold)

	for partyID, subshare := range state.receivedSubshares {
		x := new(Scalar).SetInt(uint32(partyID))
		pairs = append(pairs, &ScalarEval{X: x, Y: subshare})
	}

	// To generate new share, use Lagrange interpolation to compute
	// s'_j = Σ b_i * ŝ_ij
	newShare := ReconstructScalar(pairs)

	return newShare, nil
}

// === Helper Methods ===

// verifySubshare verifies that
// g^ŝ_ij = g^s_i * prod_{l=1}^{m' - 1} (g^a'_il)^j^l
func (n *NewShareHolder) verifySubshare(subshare *Scalar, commitment *Round1Payload) error {
	// Left side
	leftSide := new(Point)
	secp256k1.ScalarBaseMultNonConst(subshare, leftSide)

	// Right side.
	// Create polynomial from commitments: [g^s_i, g^a'_i1, g^a'_i2, ...]
	coefs := make([]*Point, len(commitment.PolyCommitments)+1)
	coefs[0] = commitment.ShareCommitment       // g^s_i (constant term)
	copy(coefs[1:], commitment.PolyCommitments) // g^a'_il coefficients

	p := PointPolynomial{Coefs: coefs}

	j := new(Scalar)
	j.SetInt(uint32(n.ID))

	rightSide := p.Eval(j)

	if !PointEqual(leftSide, rightSide) {
		return errors.New("subshare verification failed")
	}

	return nil
}

// verifySharesValid verifies that
// g^k = prod_i (g^s_i)^b_i where b_i are Lagrange coefficients
func (n *NewShareHolder) verifySharesValid(receivedCommitments map[PartyID]*Round1Payload) error {
	// Get first secret commitment (they should all be the same)
	var gk *Point
	for _, commitment := range receivedCommitments {
		if commitment.SecretCommitment != nil {
			gk = commitment.SecretCommitment
			break
		}
	}

	if gk == nil {
		return errors.New("no secret commitment found")
	}

	// Verify all secret commitments are the same
	for partyID, commitment := range receivedCommitments {
		if commitment.SecretCommitment == nil || !PointEqual(gk, commitment.SecretCommitment) {
			return fmt.Errorf("inconsistent secret commitment from party %d", partyID)
		}
	}

	// Create (x_i, g^s_i) pairs for Lagrange interpolation at zero
	pairs := make([]*PointEval, 0, n.Config.OldThreshold)

	for partyID, commitment := range receivedCommitments {
		x := new(Scalar)
		x.SetInt(uint32(partyID))
		pairs = append(pairs, &PointEval{X: x, Y: commitment.ShareCommitment})

		// Only use first m parties for interpolation
		if len(pairs) >= n.Config.OldThreshold {
			break
		}
	}

	result := ReconstructPoint(pairs)

	if !PointEqual(gk, result) {
		return errors.New("SHARES-VALID condition not satisfied")
	}

	return nil
}

// TODO: Replace with secp256k1.EquivalentNonConst from newer module version.
func PointEqual(p *Point, q *Point) bool {
	// TODO: Do we need a special case for the neutral point?
	p.ToAffine()
	q.ToAffine()
	return p.X == q.X && p.Y == q.Y && p.Z == q.Z
}
