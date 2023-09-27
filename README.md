# Qi Protocol - Crosschain Paymaster Demo

This functions equivalantly to how our crosschain paymaster functions on a live network but is managed via the local .contracts/test directory.

Execution flow is (client side):
1. user adds funds to escrow and time locks
2. user wallet inititalization code is generated
3. user selects execution chain and payment chain
4. user constructs bid to paymaster via paymasterAndData
5. userop is fully constructe and signed
6. userop is sent to our bundler network
7. if our bundler sees appropiately locked funds and tx, it will be included in the next bundle
   
Exection flow continuted (on-chain - execution chain):
1. userop is submitted to target chain entryPoint
2. userop is validated
3. userop is create code is executed if applicable
4. paymaster funds are validated
5. paymaster calls Hyperlane oracle to submit crosschain call, creates postOp context
6. transaction innerOp is executed
7. postOp crosschain call is paid for

Exection flow continuted (on-chain - origin chain):
1. Hyperlane message is receieved by escrow
2. Full user operation is validated for origin, paymaster, asset(s), sender, and account
3. Bid amount is transfered to paymasters requested disbursement account

# SETUP

git clone https://github.com/qi-protocol/crosschain-paymaster --recurse-submodules

replace .secret.example with .secret and a private key (can be anything)

forge build

forge test --match-contract PaymasterTest -vvvv