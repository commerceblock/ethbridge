# Ocean-Ethereum Bridge client

Client enabling the automated transfer of issued tokens between an Ocean sidechain and an ERC-20 token contract on Ethereum. The client uses the web3 interface for Ethereum connectivity. 

## Instructions
1. `pip3 install -r requirements.txt`
2. `python3 setup.py build && python3 setup.py install`
3. For the federation run `./run_bridge` or `python3 -m bridge` and provide the following arguments:
`--rpcconnect $HOST --rpocport $PORT --rpcuser $USER --rpcpass --oceankey $OCEANKEY $PASS --contract $CONTRACT --id $ID --ethkey $ETHKEY`

Arguments:

- `--rpconnect`: rpc host of Ocean node
- `--rpcport`: rpc port of Ocean node
- `--rpcuser`: rpc username
- `--rpcpassword`: rpc password
- `--id`: web3 (Infura) project endpoint
- `--contract`: ERC-20 contract address on Ethereum
- `--ethkey`: Private key for Ethereum token issuance
- `--hsm`: Flag to enable key generation and signing with HSM
- `--oceankey`: Private key for bridge ocean address

Example use:

