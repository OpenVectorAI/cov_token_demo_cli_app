# COVToken Demo CLI App

This python module implements the demo CLI app for the COVToken project which uses OpenVector Coprocessor to do confidential computing. This app interacts COVToken contract deployed at `0x22EC9A16c02e75d12042D9B72f6Bff3305B505Ad` on `Base Sepolia`, the contract implements a confidential/encrypted stable coin/token.

## Usage

### Prerequisites

- Python - 3.11
- pycofhe - Provided in the `artifacts/pycofhe_dist` directory, you can install `wheel` or `source dist` to install it.
- jsonchema
- web3py

To install the required packages, run:

```bash
uv sync
```

### Configuration

You need to provide a `config.json` file which will include things rpc endpoint, private key, etc. See the example config file at `artifacts/example_config.json`. The cert required is provided at `artifacts/server.pem`. Also the ABI for COVToken contract is provided at `artifacts/abi.json`.

### Running the CLI

To run the CLI, use the following command:

```bash
python src/cov_token_demo_cli_app/cov_token.py config_file_path
```

Remember to run the above command from the project virtual environment. To activate the virtual environment, run:

```bash
source .venv/bin/activate
```

## Miscellaneous

You can find the COVToken contract in the [openvector_coprocessor](https://github.com/OpenVectorAI/openvector_coprocesssor) repo, specifically at the `frontend/eth_sol/contracts/examples/cov_token.sol`.

For pycofhe, please see the [pycofhe](https://github.com/OpenVectorAI/pycofhe) repo.

The program uses the endpoint `https://openvector.cofhe.dev:8001/api/v1` to get the latest OpenVector Coprocessor network details.