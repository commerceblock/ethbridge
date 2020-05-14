# Ocean-Ethereum Bridge client

Client enabling the automated transfer of issued tokens between an Ocean sidechain and an ERC-20 token contract on Ethereum. The client uses the web3 interface for Ethereum connectivity. 

The client connects to an Ocean sidechain via an RPC connection to an `oceand` client, and to the Ethereum network via an Infura project with the `web3.py` interface. The client is configured with two private keys: `$OCEANKEY` and `$ETHKEY`. `$OCEANKEY` defines the address that tokens are paid to on the sidechain, and `$ETHKEY` controls the issuance of tokens on Ethereum. 

The client watches for transactions on both chains: when a payment to the `$OCEANKEY` address is detected on the sidechain, the client then issues an equivalent token from the Ethereum contract to the same address that sent the tokens on the sidechain. 

When a transfer to the contract burn address is detected on the Ethereum chain, the clent identifies the address of sending Ethereum account and first verifies that the same address is whitelisted on the sidechain. If it is, then the client makes a payment of the equivalent amount of token to the address from the `$OCEANKEY` wallet on the sidechain (minus transaction fee). If the address is not whitelisted, then the client re-issues the equivalent amount of token back to the address on Ethereum. 

## Instructions
1. `pip3 install -r requirements.txt`
2. `python3 setup.py build && python3 setup.py install`
3. To run the client `./run_bridge` or `python3 -m bridge` and provide the following arguments:
`--rpcconnect $HOST --rpocport $PORT --rpcuser $USER --rpcpass --oceankey $OCEANKEY $PASS --contract $CONTRACT --id $ID --ethkey $ETHKEY`

Arguments:

- `--rpconnect`: rpc host of Ocean node
- `--rpcport`: rpc port of Ocean node
- `--rpcuser`: rpc username
- `--rpcpassword`: rpc password
- `--id`: web3 (Infura) project endpoint
- `--contract`: ERC-20 contract address on Ethereum
- `--burnaddress`: ERC-20 contract burn address
- `--ethkey`: Private key for Ethereum token issuance
- `--hsm`: Flag to enable key generation and signing with HSM
- `--oceankey`: Private key for bridge ocean address

Example use:

