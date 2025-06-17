package task

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pbspark "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/gossip"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/tokentransaction"
	"github.com/lightsparkdev/spark/so/ent/transfer"
	"github.com/lightsparkdev/spark/so/ent/tree"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/ent/utxoswap"
	"github.com/lightsparkdev/spark/so/handler"
	"github.com/lightsparkdev/spark/so/lrc20"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	defaultTaskTimeout              = 1 * time.Minute
	dkgTaskTimeout                  = 3 * time.Minute
	deleteStaleTreeNodesTaskTimeout = 10 * time.Minute

	errTaskTimeout = fmt.Errorf("task timed out")
)

// Task is a task that is scheduled to run.
type Task struct {
	// Name is the human-readable name of the task.
	Name string
	// Duration is the duration between each run of the task.
	Duration time.Duration
	// Timeout is the maximum time the task is allowed to run before it will be cancelled.
	Timeout *time.Duration
	// Whether to run the scheduled task in the hermetic test environment.
	RunInTestEnv bool
	// Task is the function that is run when the task is scheduled.
	Task func(context.Context, *so.Config, *lrc20.Client) error
}

// AllTasks returns all the tasks that are scheduled to run.
func AllTasks() []Task {
	return []Task{
		{
			Name:         "dkg",
			Duration:     10 * time.Second,
			Timeout:      &dkgTaskTimeout,
			RunInTestEnv: false,
			Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
				return ent.RunDKGIfNeeded(ctx, config)
			},
		},
		{
			Name:         "cancel_expired_transfers",
			Duration:     1 * time.Minute,
			RunInTestEnv: true,
			Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
				logger := logging.GetLoggerFromContext(ctx)
				h := handler.NewTransferHandler(config)

				db := ent.GetDbFromContext(ctx)
				query := db.Transfer.Query().Where(
					transfer.And(
						transfer.StatusIn(st.TransferStatusSenderInitiated, st.TransferStatusSenderKeyTweakPending),
						transfer.ExpiryTimeLT(time.Now()),
						transfer.ExpiryTimeNEQ(time.Unix(0, 0)),
					),
				)

				transfers, err := query.All(ctx)
				if err != nil {
					return err
				}

				for _, transfer := range transfers {
					err := h.CancelTransferInternal(ctx, transfer.ID.String())
					if err != nil {
						logger.Error("failed to cancel transfer", "error", err)
					}
				}

				return nil
			},
		},
		{
			Name:         "delete_stale_pending_trees",
			Duration:     1 * time.Hour,
			Timeout:      &deleteStaleTreeNodesTaskTimeout,
			RunInTestEnv: false,
			Task: func(ctx context.Context, _ *so.Config, _ *lrc20.Client) error {
				logger := logging.GetLoggerFromContext(ctx)
				tx := ent.GetDbFromContext(ctx)

				// Find tree nodes that are:
				// 1. Older than 5 days
				// 2. Have status "CREATING"
				// 3. Belong to trees with status "PENDING"
				query := tx.TreeNode.Query().Where(
					treenode.And(
						treenode.StatusEQ(st.TreeNodeStatusCreating),
						treenode.CreateTimeLTE(time.Now().Add(-5*24*time.Hour)),
						treenode.HasTreeWith(tree.StatusEQ(st.TreeStatusPending)),
					),
				).WithTree()

				treeNodes, err := query.All(ctx)
				if err != nil {
					logger.Error("failed to query tree nodes", "error", err)
					return err
				}

				if len(treeNodes) == 0 {
					logger.Info("Found no stale tree nodes.")
					return nil
				}

				treeToTreeNodes := make(map[uuid.UUID][]uuid.UUID)
				for _, node := range treeNodes {
					treeID := node.Edges.Tree.ID
					treeToTreeNodes[treeID] = append(treeToTreeNodes[treeID], node.ID)
				}

				for treeID, treeNodeIDs := range treeToTreeNodes {
					logger.Info(fmt.Sprintf("Deleting stale tree %s along with associated tree nodes (%d in total).", treeID, len(treeNodeIDs)))

					numDeleted, err := tx.TreeNode.Delete().Where(
						treenode.IDIn(treeNodeIDs...),
					).Exec(ctx)
					if err != nil {
						logger.Error("failed to delete tree nodes", "tree_id", treeID, "error", err)
						return err
					}

					logger.Info(fmt.Sprintf("Deleted %d tree nodes.", numDeleted))

					// Delete the associated trees
					_, err = tx.Tree.Delete().Where(tree.IDEQ(treeID)).Exec(ctx)
					if err != nil {
						logger.Error("failed to delete tree", "tree_id", treeID, "error", err)
						return err
					}

					logger.Info(fmt.Sprintf("Deleted tree %s.", treeID))
				}

				return nil
			},
		},
		{
			Name:     "resume_send_transfer",
			Duration: 5 * time.Minute,
			Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
				logger := logging.GetLoggerFromContext(ctx)
				h := handler.NewTransferHandler(config)

				db := ent.GetDbFromContext(ctx)
				query := db.Transfer.Query().Where(
					transfer.And(
						transfer.StatusEQ(st.TransferStatusSenderInitiatedCoordinator),
					),
				).Limit(1000)

				transfers, err := query.All(ctx)
				if err != nil {
					return err
				}

				for _, transfer := range transfers {
					err := h.ResumeSendTransfer(ctx, transfer)
					if err != nil {
						logger.Error("failed to resume send transfer", "error", err)
					}
				}
				return nil
			},
		},
		{
			Name:         "cancel_or_finalize_expired_token_transactions",
			Duration:     1 * time.Hour,
			RunInTestEnv: true,
			Task: func(ctx context.Context, config *so.Config, lrc20Client *lrc20.Client) error {
				logger := logging.GetLoggerFromContext(ctx)
				currentTime := time.Now()

				h := handler.NewInternalTokenTransactionHandler(config, lrc20Client)
				logger.Info("Checking for expired token transactions",
					"current_time", currentTime.Format(time.RFC3339))
				// TODO: Consider adding support for expiring mints as well (although not strictly needed
				// because mints do not lock TTXOs).
				db := ent.GetDbFromContext(ctx)
				expiredTransfersQuery := db.TokenTransaction.
					Query().
					ForUpdate().
					WithCreatedOutput().
					WithSpentOutput(func(q *ent.TokenOutputQuery) {
						// Needed to enable marshalling of the token transaction proto.
						q.WithOutputCreatedTokenTransaction()
					}).Where(
					tokentransaction.And(
						// Transfer transactions are effectively pending in either STARTED or SIGNED state.
						// Note that different SOs may have different states if SIGNED calls did not succeed with all SOs.
						tokentransaction.StatusIn(st.TokenTransactionStatusStarted, st.TokenTransactionStatusSigned),
						tokentransaction.Not(tokentransaction.HasMint()),
						tokentransaction.ExpiryTimeLT(currentTime),
						tokentransaction.ExpiryTimeNEQ(time.Unix(0, 0)),
					),
				)
				expiredTransferTransactions, err := expiredTransfersQuery.All(ctx)
				if err != nil {
					logger.Error(fmt.Sprintf("Failed to query expired transfer token transactions: %v", err))
				}
				logger.Info(fmt.Sprintf("Expired token transactions query completed, found %d expired transfers", len(expiredTransferTransactions)))

				for _, expiredTransaction := range expiredTransferTransactions {
					txFinalHash := hex.EncodeToString(expiredTransaction.FinalizedTokenTransactionHash)
					expiryTime := expiredTransaction.ExpiryTime.Format(time.RFC3339)

					logger.Info(fmt.Sprintf("Attempting to cancel or finalize expired token transaction: id=%s, hash=%s, expiry=%s, status=%s",
						expiredTransaction.ID,
						txFinalHash,
						expiryTime,
						expiredTransaction.Status))

					err = h.CancelOrFinalizeExpiredTokenTransaction(ctx, config, expiredTransaction)
					if err != nil {
						logger.Error(fmt.Sprintf("Failed to cancel or finalize expired token transaction: id=%s, hash=%s, error=%v",
							expiredTransaction.ID,
							txFinalHash,
							err))
					} else {
						logger.Info(fmt.Sprintf("Successfully cancelled or finalized expired token transaction: id=%s, hash=%s",
							expiredTransaction.ID,
							txFinalHash))
					}
				}
				return nil
			},
		},
		{
			Name:         "send_gossip",
			Duration:     5 * time.Minute,
			RunInTestEnv: true,
			Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
				logger := logging.GetLoggerFromContext(ctx)
				handler := handler.NewSendGossipHandler(config)
				db := ent.GetDbFromContext(ctx)
				query := db.Gossip.Query().Where(gossip.StatusEQ(st.GossipStatusPending)).Limit(1000)
				gossips, err := query.ForUpdate().All(ctx)
				if err != nil {
					return err
				}

				for _, gossip := range gossips {
					_, err := handler.SendGossipMessage(ctx, gossip)
					if err != nil {
						logger.Error("failed to send gossip", "error", err)
					}
				}
				return nil
			},
		},
		{
			Name:         "complete_utxo_swap",
			Duration:     1 * time.Minute,
			RunInTestEnv: true,
			Task: func(ctx context.Context, config *so.Config, _ *lrc20.Client) error {
				logger := logging.GetLoggerFromContext(ctx)
				db := ent.GetDbFromContext(ctx)

				query := db.UtxoSwap.Query().
					Where(utxoswap.StatusEQ(st.UtxoSwapStatusCreated)).
					Where(utxoswap.CoordinatorIdentityPublicKeyEQ(config.IdentityPublicKey())).
					Order(utxoswap.ByCreateTime(sql.OrderDesc())).
					Limit(100)

				utxoSwaps, err := query.All(ctx)
				if err != nil {
					return err
				}

				for _, utxoSwap := range utxoSwaps {
					transfer, err := utxoSwap.QueryTransfer().Only(ctx)
					if err != nil && !ent.IsNotFound(err) {
						logger.Error("failed to get transfer for a utxo swap", "error", err)
						continue
					}
					if transfer == nil && utxoSwap.RequestType != st.UtxoSwapRequestTypeRefund {
						logger.Debug("No transfer found for a non-refund utxo swap", "utxo_swap_id", utxoSwap.ID)
						continue
					}
					if utxoSwap.RequestType == st.UtxoSwapRequestTypeRefund || transfer.Status == st.TransferStatusCompleted {
						logger.Debug("Marking utxo swap as completed", "utxo_swap_id", utxoSwap.ID)

						utxo, err := utxoSwap.QueryUtxo().Only(ctx)
						if err != nil {
							return fmt.Errorf("unable to get utxo: %w", err)
						}
						protoNetwork, err := common.ProtoNetworkFromSchemaNetwork(utxo.Network)
						if err != nil {
							return fmt.Errorf("unable to get proto network: %w", err)
						}
						protoUtxo := &pbspark.UTXO{
							Txid:    utxo.Txid,
							Vout:    utxo.Vout,
							Network: protoNetwork,
						}

						completedUtxoSwapRequest, err := handler.CreateCompleteSwapForUtxoRequest(config, protoUtxo)
						if err != nil {
							logger.Warn("Failed to get complete swap for utxo request, cron task to retry", "error", err)
						} else {
							h := handler.NewInternalDepositHandler(config)
							if err := h.CompleteSwapForAllOperators(ctx, config, completedUtxoSwapRequest); err != nil {
								logger.Warn("Failed to mark a utxo swap as completed in all operators, cron task to retry", "error", err)
							}
						}
					}
				}
				return nil
			},
		},
	}
}

func (t *Task) Schedule(scheduler gocron.Scheduler, config *so.Config, db *ent.Client, lrc20Client *lrc20.Client) error {
	_, err := scheduler.NewJob(
		gocron.DurationJob(t.Duration),
		gocron.NewTask(t.createWrappedTask(), config, db, lrc20Client),
		gocron.WithName(t.Name),
	)
	if err != nil {
		return err
	}

	return nil
}

func (t *Task) createWrappedTask() func(context.Context, *so.Config, *ent.Client, *lrc20.Client) error {
	return func(ctx context.Context, config *so.Config, db *ent.Client, lrc20Client *lrc20.Client) error {
		logger := logging.GetLoggerFromContext(ctx).
			With("task.name", t.Name).
			With("task.id", uuid.New().String())

		ctx = logging.Inject(ctx, logger)

		timeout := t.getTimeout()
		ctx, cancel := context.WithTimeoutCause(ctx, timeout, errTaskTimeout)
		defer cancel()

		done := make(chan error, 1)

		inner := func(context.Context, *so.Config, *lrc20.Client) error {
			tx, err := db.Tx(ctx)
			if err != nil {
				return err
			}

			ctx = ent.Inject(ctx, tx)

			err = t.Task(ctx, config, lrc20Client)
			if err != nil {
				logger.Error("Task failed!", "error", err)

				rollbackErr := tx.Rollback()
				if rollbackErr != nil {
					logger.Warn("Failed to rollback transaction after task failure", "error", rollbackErr)
				}

				return err
			}

			return tx.Commit()
		}

		logger.Info("Starting task")

		go func() {
			done <- inner(ctx, config, lrc20Client)
		}()

		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			if context.Cause(ctx) == errTaskTimeout {
				logger.Warn("Task timed out!")
				return ctx.Err()
			}

			logger.Warn("Context done before task completion! Are we shutting down?", "error", ctx.Err())
			return ctx.Err()
		}
	}
}

// Returns the configured timeout of the task if non-null, otherwise returns the default.
func (t *Task) getTimeout() time.Duration {
	if t.Timeout != nil {
		return *t.Timeout
	}
	return defaultTaskTimeout
}

type Monitor struct {
	taskCount    metric.Int64Counter
	taskDuration metric.Float64Histogram
}

func NewMonitor() (*Monitor, error) {
	meter := otel.Meter("gocron")

	jobCount, err := meter.Int64Counter(
		"gocron.task_count_total",
		metric.WithDescription("Total number of tasks executed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create task count metric: %w", err)
	}

	jobDuration, err := meter.Float64Histogram(
		"gocron.task_duration_milliseconds",
		metric.WithDescription("Duration of tasks in milliseconds."),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(
			// Replace the buckets at the lower end (e.g. 5, 10, 25, 50, 75ms) with buckets up to 60s, to
			// capture the longer task durations.
			100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000, 15000, 30000, 45000, 60000,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create task duration metric: %w", err)
	}

	return &Monitor{
		taskCount:    jobCount,
		taskDuration: jobDuration,
	}, nil
}

func (t *Monitor) IncrementJob(_ uuid.UUID, name string, _ []string, status gocron.JobStatus) {
	t.taskCount.Add(
		context.Background(),
		1,
		metric.WithAttributes(
			attribute.String("task.name", name),
			attribute.String("task.result", string(status)),
		),
	)
}

func (t *Monitor) RecordJobTiming(startTime, endTime time.Time, _ uuid.UUID, name string, _ []string) {
	duration := endTime.Sub(startTime).Milliseconds()
	t.taskDuration.Record(
		context.Background(),
		float64(duration),
		metric.WithAttributes(
			attribute.String("task.name", name),
		),
	)
}
