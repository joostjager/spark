# @buildonspark/spark-sdk

## 0.1.40

### Patch Changes

- Improved support for unilateral exits

## 0.1.39

### Patch Changes

- - Update leaves swap to v2

## 0.1.38

### Patch Changes

- - Export errors and utils from /native

## 0.1.37

### Patch Changes

- - Return static deposit address instead of throwing error when trying to create after first time.
  - Handle window undefined in buffer polyfill.
  - Add static deposit transactions to get all transaction request.

## 0.1.36

### Patch Changes

- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.57

## 0.1.35

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.56

## 0.1.34

### Patch Changes

- Add ability to create invoice for another spark user
- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.55

## 0.1.33

### Patch Changes

- - Remove some unneeded files to reduce package size
  - Include Android binding libs

## 0.1.32

### Patch Changes

- - Added HDKeyGenerator interface and default implementation to allow for easy custom derivation path changes

## 0.1.31

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.54

## 0.1.30

### Patch Changes

- Remove LRC20 Proto Generation
- Update to leaf optimizations
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.53

## 0.1.29

### Patch Changes

- - react-native moved to peerDependencies
  - Error messages now include more context and the original error message.
  - Fix self transfers with query to pending transactions.
  - For RN Android, improved typings and resolve issue where calls to SparkFrostModule were hanging.
  - Export getLatestDepositTxId from /native
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.52

## 0.1.28

### Patch Changes

- - Separate entry point for NodeJS environments and refactor some NodeJS dependencies out
  - Added `LEAVES_LOCKED` status to `SparkLeavesSwapRequestStatus` enum.
  - Added support for `GetTransferPackageSigningPayload` in `SparkTransferToLeavesConnection`.
  - Added GraphQL for managing static deposit addresses.
  - Begin adding "Transfer V2", a new mechanism for handling transfers.
    - A new method `sendTransferWithKeyTweaks` added to `TransferService`.
    - SparkWallet primary transfer initiation now utilizes this V2 flow.
  - Export the `createDummyTx` function from WASM bindings. Primarily for testing or example purposes.
  - The `swapLeaves` method in `SparkWallet` now processes leaves in batches of 100, potentially improving performance and reliability for operations involving a large number of leaves.
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.51

## 0.1.27

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.50

## 0.1.26

### Patch Changes

- - Export ReactNativeSigner as DefaultSparkSigner from /native

## 0.1.25

### Patch Changes

- - Only import @opentelemetry in NodeJS

## 0.1.24

### Patch Changes

- - Add tracer
  - Token transfer with multiple outputs

## 0.1.23

### Patch Changes

- Use browser module override for nice-grpc
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.49

## 0.1.22

### Patch Changes

- Update homepage URL
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.48

## 0.1.21

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.47

## 0.1.20

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.46

## 0.1.19

### Patch Changes

- React Native support
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.45

## 0.1.18

### Patch Changes

- - Polyfill crypto for React Native support

## 0.1.17

### Patch Changes

- - Removed the nice-grpc-web alias from bundling configuration
  - Refactored ConnectionManager and gRPC client code in src/services/connection.ts to support Node vs Web channels uniformly
  - Changed rawTx serialization to toBytes(true) for script sig in DepositService
  - Moved isHermeticTest helper from src/tests/test-util.ts to src/tests/isHermeticTest.ts
  - Wrapped claimTransfers in SparkWallet (src/spark-wallet.ts) with a try/catch, improved retry logic, and updated return type to an array of claimed-ID strings
  - Updated utils in src/utils/bitcoin.ts and src/utils/network.ts to use the new serialization methods and constants paths
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.44

## 0.1.16

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.43

## 0.1.15

### Patch Changes

- - Fixed secret splitting by passing threshold (instead of threshold - 1) to the polynomial generator.

## 0.1.14

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.42

## 0.1.13

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.41

## 0.1.12

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.40

## 0.1.11

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.39

## 0.1.10

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.38

## 0.1.9

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.37

## 0.1.8

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.36

## 0.1.7

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.35

## 0.1.6

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.34

## 0.1.5

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.33

## 0.1.4

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.32

## 0.1.3

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.31

## 0.1.2

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.30

## 0.1.1

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.29

## 0.1.0

### Minor Changes

- - SparkServiceClient.query_all_transfers request format has changed to TransferFilter type

## 0.0.30

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.28

## 0.0.29

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.27

## 0.0.28

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.26

## 0.0.27

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.25

## 0.0.26

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.24

## 0.0.25

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.23

## 0.0.24

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.22

## 0.0.23

### Patch Changes

- CJS support and package improvements
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.21

## 0.0.22

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.20

## 0.0.21

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.19

## 0.0.20

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.18

## 0.0.19

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.17

## 0.0.18

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.16

## 0.0.17

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.15

## 0.0.16

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.14

## 0.0.15

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.13

## 0.0.14

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.12

## 0.0.13

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.11

## 0.0.12

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.10

## 0.0.11

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.9

## 0.0.10

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.8

## 0.0.9

### Patch Changes

- Fixes
- Updated dependencies
  - @buildonspark/lrc20-sdk@0.0.7

## 0.0.8

### Patch Changes

- Fixes

## 0.0.7

### Patch Changes

- Fixes

## 0.0.6

### Patch Changes

- Fixes

## 0.0.4

### Patch Changes

- Fixes

## 0.0.3

### Patch Changes

- Fixes

## 0.0.2

### Patch Changes

- Fixes

## 0.0.1

### Patch Changes

- Fixes
