from __future__ import annotations

import argparse
from base64 import b64decode, b64encode
from dataclasses import dataclass
from enum import Enum
import json
import os
from time import sleep
from typing import Tuple
from jsonschema import ValidationError, validate
import requests
from web3 import Account, Web3, HTTPProvider
from web3.middleware import SignAndSendRawMiddlewareBuilder
from web3.types import Wei
from web3.contract import Contract

from pycofhe.network import (
    NetworkDetails,
    ServiceType,
    ProtocolVersion,
    Request,
    ResponseStatus,
    Response,
    SetupNodeRequestType,
    SetupNodeRequest,
    SetupNodeResponseStatus,
    SetupNodeResponse,
    NetworkDetailsRequestType,
    NetworkDetailsRequest,
    NetworkDetailsResponseStatus,
    NetworkDetailsResponse,
    make_cpu_cryptosystem_client_node,
    CPUCryptoSystemClientNode,
    encrypt_bit as encrypt_single,
    serialize_bit as serialize_single,
    deserialize_bit as deserialize_single,
)

TRANSCATION_SLEEP_TIMEOUT = 5
WAIT_BETWEEN_STEPS = 3 * TRANSCATION_SLEEP_TIMEOUT
TRANSCATION_FAILURE_SLEEP_TIMEOUT = 10


def sleep_after_transcation():
    sleep(TRANSCATION_SLEEP_TIMEOUT)


def sleep_after_transaction_failure():
    sleep(TRANSCATION_FAILURE_SLEEP_TIMEOUT)


N_BASE_PAYMENT = 163000 * 1000000000
O_BASE_PAYMENT = 1000
BASE_PAYMENT = N_BASE_PAYMENT + O_BASE_PAYMENT
PAYMENT_CALLBACK_PAYMENT = 30000 * 1000000000
TRANSFER_FUNC_CALLBACK_PAYMENT = 80000 * 1000000000
TRANSFER_FUNC_PAYMENT = (
    BASE_PAYMENT + TRANSFER_FUNC_CALLBACK_PAYMENT + PAYMENT_CALLBACK_PAYMENT
)
MINT_FUNC_CALLBACK_PAYMENT = 60000 * 1000000000
MINT_FUNC_PAYMENT = BASE_PAYMENT + MINT_FUNC_CALLBACK_PAYMENT + PAYMENT_CALLBACK_PAYMENT
UPDATE_REENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT = 2000000 * 1000000000
UPDATE_REENCRYPTED_BALANCE_FUNC_PAYMENT = (
    BASE_PAYMENT
    + UPDATE_REENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT
    + PAYMENT_CALLBACK_PAYMENT
)
UPDATE_ENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT = 200000 * 1000000000
UPDATE_ENCRYPTED_BALANCE_FUNC_PAYMENT = (
    BASE_PAYMENT
    + UPDATE_ENCRYPTED_BALANCE_FUNC_CALLBACK_PAYMENT
    + PAYMENT_CALLBACK_PAYMENT
)
REGISTER_KEY_FUNC_ACCEPTANCE_CALLBACK_PAYMENT = 30000 * 1000000000
REGISTER_KEY_FUNC_SUBMISSION_CALLBACK_PAYMENT = 100000 * 1000000000
REGISTER_KEY_FUNC_PAYMENT = (
    BASE_PAYMENT
    + REGISTER_KEY_FUNC_ACCEPTANCE_CALLBACK_PAYMENT
    + REGISTER_KEY_FUNC_SUBMISSION_CALLBACK_PAYMENT
    + PAYMENT_CALLBACK_PAYMENT
)


def set_default_account(w3: Web3, private_key: str) -> None:
    w3.eth.default_account = Account.from_key(private_key).address


first_time = True


def set_middleware_and_default_account(w3: Web3, s_private_key: str) -> None:
    global first_time
    if not first_time:
        w3.middleware_onion.remove(
            "signer",
        )
    else:
        first_time = False
    w3.middleware_onion.inject(
        SignAndSendRawMiddlewareBuilder.build(s_private_key),
        layer=0,
        name="signer",
    )
    set_default_account(w3, s_private_key)


@dataclass(frozen=True, slots=True)
class Config:
    provider_uri: str
    contract_address: str
    ov_token_contract_address: str
    openvector_relayer_endpoint_url: str
    contract_abi_file_path: str
    ov_token_contract_abi_file_path: str
    cert_path: str
    private_key: str = ""
    rsa_private_key_path: str = ""
    rsa_public_key_path: str = ""
    sender_account_private_key: str = ""
    recipient_account_private_key: str = ""


def read_json_file(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


def read_json_config(file_path, schema):
    config = read_json_file(file_path)
    validate(config, schema)
    return config


config_schema = {
    "type": "object",
    "properties": {
        "provider_uri": {"type": "string"},
        "contract_address": {"type": "string"},
        "ov_token_contract_address": {"type": "string"},
        "openvector_relayer_endpoint_url": {"type": "string"},
        "contract_abi_file_path": {"type": "string"},
        "ov_token_contract_abi_file_path": {"type": "string"},
        "cert_path": {"type": "string"},
        "private_key": {"type": "string"},
        "rsa_private_key_path": {"type": "string"},
        "rsa_public_key_path": {"type": "string"},
        "sender_account_private_key": {"type": "string"},
        "recipient_account_private_key": {"type": "string"},
    },
    "required": [
        "provider_uri",
        "contract_address",
        "ov_token_contract_address",
        "openvector_relayer_endpoint_url",
        "contract_abi_file_path",
        "ov_token_contract_abi_file_path",
        "cert_path",
    ],
}


class Mode(Enum):
    TEST = "test"
    CLI_APP = "cli_app"


def print_in_test_mode(message: str, mode: Mode) -> None:
    if mode == Mode.TEST:
        print(message)


def load_config(config_path: str, mode: Mode) -> Config:
    try:
        config = read_json_config(config_path, config_schema)
        config = Config(
            config["provider_uri"],
            config["contract_address"],
            config["ov_token_contract_address"],
            config["openvector_relayer_endpoint_url"],
            config["contract_abi_file_path"],
            config["ov_token_contract_abi_file_path"],
            config["cert_path"],
            config.get("private_key", ""),
            config.get("rsa_private_key_path", ""),
            config.get("rsa_public_key_path", ""),
            config.get("sender_account_private_key", ""),
            config.get("recipient_account_private_key", ""),
        )
        if mode == Mode.TEST:
            if (
                not config.sender_account_private_key
                or not config.recipient_account_private_key
            ):
                raise ValueError(
                    "sender_account_private_key and recipient_account_private_key should not be set in test mode"
                )
        elif mode == Mode.CLI_APP:
            if not config.private_key:
                raise ValueError("private_key should be set in cli_app mode")
        else:
            raise ValueError("Invalid mode")
        return config
    except json.JSONDecodeError as e:
        print(f"Failed to decode JSON config file: {e}")
        raise
    except ValidationError as e:
        print(f"Config file does not match schema: {e}")
        raise
    except Exception as e:
        print(f"An error occurred while loading the config file: {e}")
        raise


def get_network_details(relayer_url: str) -> NetworkDetails:
    try:
        network_details_req = NetworkDetailsRequest(NetworkDetailsRequestType.GET, b"")
        setup_node_req = SetupNodeRequest(
            SetupNodeRequestType.NetworkDetailsRequest,
            network_details_req.to_string(),
        )
        req = Request(
            ProtocolVersion.V1,
            ServiceType.SETUP_REQUEST,
            setup_node_req.to_string(),
        )
        data = b64encode(req.to_string()).decode("utf-8")
        rpc_req = {"data": data}
        res = requests.post(
            url=f"{relayer_url}/openvector/rpc/", data=json.dumps(rpc_req)
        )

        if res.status_code == 200:
            data = res.json()
            if not isinstance(data, dict):
                raise ValueError("Invalid response from server")
            if "status" not in data or "data" not in data:
                raise ValueError("Invalid response from server")
            if not isinstance(data["status"], int):
                raise ValueError("Invalid status code in response")
            if not isinstance(data["data"], str):
                raise ValueError("Invalid data in response")
            if data["status"] == 200:
                response = Response.from_string(
                    b64decode(data["data"]),
                )
                if response.status != ResponseStatus.OK:
                    raise ValueError(
                        f"Failed to fetch network details, status code: {response.status}"
                    )
                setup_res = SetupNodeResponse.from_string(
                    response.data,
                )
                if setup_res.status != SetupNodeResponseStatus.OK:
                    raise ValueError(
                        f"Failed to fetch network details, status code: {setup_res.status}"
                    )
                network_details_response = NetworkDetailsResponse.from_string(
                    setup_res.data,
                )
                if network_details_response.status != NetworkDetailsResponseStatus.OK:
                    raise ValueError(
                        f"Failed to fetch network details, status code: {network_details_response.status}"
                    )
                return NetworkDetails.from_string(
                    network_details_response.data,
                )
            else:
                raise ValueError(
                    f"Failed to fetch network details, status code: {res.status_code}"
                )
        else:
            raise ValueError(
                f"Failed to fetch network details, status code: {res.status_code}"
            )
    except Exception as e:
        print(f"Failed to fetch network details: {e}")
        raise


def get_cpu_cryptosystem_client_node(
    url: str, cert_path: str
) -> CPUCryptoSystemClientNode:
    nd = get_network_details(url)
    return make_cpu_cryptosystem_client_node(nd, cert_path)


def setup(
    config_path: str,
    mode: Mode,
) -> Tuple[Web3, CPUCryptoSystemClientNode, Contract, Contract, str, str]:
    print_in_test_mode("Setting up", mode)
    print_in_test_mode("Loading config file", mode)
    config = load_config(config_path, mode)

    print_in_test_mode(f"Connecting to HTTPProvider", mode)
    w3 = Web3(HTTPProvider(config.provider_uri))

    # print("Sleeping for 2 seconds")
    sleep(2)
    print_in_test_mode("Checking connection", mode)
    if not w3.is_connected():
        print("Failed to connect to provider")
        exit(1)
    print(f"Connected to {w3.client_version}")

    print(
        f"Loading contract at {config.contract_address} and ABI as per given JSON file"
    )
    contract = w3.eth.contract(
        address=config.contract_address,  # type: ignore
        abi=json.load(open(config.contract_abi_file_path, "r")),
    )
    print(
        f"Loading OV token contract at {config.ov_token_contract_address} and ABI as per given JSON file"
    )
    ov_token_contract = w3.eth.contract(
        address=config.ov_token_contract_address,  # type: ignore
        abi=json.load(open(config.ov_token_contract_abi_file_path, "r")),
    )
    cn = get_cpu_cryptosystem_client_node(
        config.openvector_relayer_endpoint_url,
        config.cert_path,
    )
    if mode == Mode.CLI_APP:
        print_in_test_mode("Setting default account", mode)
        set_default_account(w3, config.private_key)
    return (
        w3,
        cn,
        contract,
        ov_token_contract,
        (
            config.private_key
            if mode == Mode.CLI_APP
            else config.sender_account_private_key
        ),
        config.recipient_account_private_key if mode == Mode.TEST else "",
    )


def submit_ov_token_mint_request(
    w3: Web3,
    ov_token_contract: Contract,
    sender: str,
    recipient: str,
    amount: int,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call:
        print(f"Submitting OV token mint request for {amount} to {recipient}")
    try:
        tx_hash = ov_token_contract.functions.mint(recipient, amount).transact(
            {"from": sender}
        )
        sleep_after_transcation()
        print("OV token mint request submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit OV token mint request: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying OV token mint request")
            submit_ov_token_mint_request(
                w3, ov_token_contract, sender, recipient, amount, False
            )
        else:
            print("OV token mint request cancelled")
            return


def submit_ov_token_approve_request(
    w3: Web3,
    ov_token_contract: Contract,
    sender: str,
    spender: str,
    amount: int,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call:
        print(f"Submitting OV token approve request for {amount} to {spender}")
    try:
        tx_hash = ov_token_contract.functions.approve(spender, amount).transact(
            {"from": sender}
        )
        sleep_after_transcation()
        print("OV token approve request submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit OV token approve request: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying OV token approve request")
            submit_ov_token_approve_request(
                w3, ov_token_contract, sender, spender, amount, False
            )
        else:
            print("OV token approve request cancelled")
            return


def get_ov_token_balance(
    w3: Web3,
    ov_token_contract: Contract,
    account: str,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> int:
    if first_call:
        print(f"Getting OV token balance for {account}")

    try:
        balance = ov_token_contract.functions.balanceOf(account).call()
        print(f"OV token balance: {balance}")
        return balance
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to get OV token balance: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying OV token balance fetch")
            return get_ov_token_balance(w3, ov_token_contract, account, False)
        else:
            print("OV token balance fetch cancelled")
            return -1


def get_eth_balance(
    w3: Web3,
    account: str,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> int:
    if first_call:
        print(f"Getting ETH balance for {account}")

    try:
        balance = w3.eth.get_balance(account)
        print(f"ETH balance: {balance}")
        return balance
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to get ETH balance: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying ETH balance fetch")
            return get_eth_balance(w3, account, False)
        else:
            print("ETH balance fetch cancelled")
            return -1


def get_conversion_rate(
    contract: Contract,
) -> Tuple[int, int]:
    try:
        ov_conversion_rate = contract.functions.getOVTokenToCOVTokenRatio().call()
        eth_conversion_rate = contract.functions.getEthToCOVTokenRatio().call()
        return ov_conversion_rate, eth_conversion_rate
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to get conversion rate: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying conversion rate fetch")
            return get_conversion_rate(contract)
        else:
            print("Conversion rate fetch cancelled")
            return -1, -1


def submit_mint_request(
    w3: Web3,
    client: CPUCryptoSystemClientNode,
    contract: Contract,
    amount: int,
    sender: str,
    recipient: str,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call:
        print(f"Submitting mint request for {amount} to {recipient}")
    enc_amount = encrypt_single(
        client.cryptosystem, client.network_encryption_key, amount
    )
    ser_amount = serialize_single(client.cryptosystem, enc_amount)
    if first_call:
        print(f"Serialized Encrypted Amount: {ser_amount.hex()}")
    try:
        tx_hash = contract.functions.mint(recipient, ser_amount).transact(
            {"from": sender, "value": Wei(MINT_FUNC_PAYMENT)}
        )
        sleep_after_transcation()
        print("Mint request submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit mint request: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying mint request")
            submit_mint_request(w3, client, contract, amount, sender, recipient, False)
        else:
            print("Mint request cancelled")
            return


def submit_mint_with_ov_token_request(
    w3: Web3,
    contract: Contract,
    ov_token_contract: Contract,
    amount: int,
    sender: str,
    recipient: str,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call:
        print(f"Submitting mint request using OV token for {amount} to {recipient}")
    try:
        tx_hash = contract.functions.mintFromOVToken(recipient, amount).transact(
            {"from": sender, "value": Wei(MINT_FUNC_PAYMENT)}
        )
        sleep_after_transcation()
        print("Mint request using OV token submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit mint request using OV token: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying mint request using OV token")
            submit_mint_with_ov_token_request(
                w3, contract, ov_token_contract, amount, sender, recipient, False
            )
        else:
            print("Mint request using OV token cancelled")
            return


def submit_mint_with_eth_request(
    w3: Web3,
    contract: Contract,
    amount: int,
    sender: str,
    recipient: str,
    conversion_rate: int,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call:
        print(f"Submitting mint request using ETH for {amount} to {recipient}")
    try:
        tx_hash = contract.functions.mintFromEth(recipient, amount).transact(
            {"from": sender, "value": Wei(MINT_FUNC_PAYMENT + amount * conversion_rate)}
        )
        sleep_after_transcation()
        print("Mint request using ETH submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit mint request using ETH: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying mint request using ETH")
            submit_mint_with_eth_request(w3, contract, amount, sender, recipient, False)
        else:
            print("Mint request using ETH cancelled")
            return


def submit_transfer_request(
    w3: Web3,
    client: CPUCryptoSystemClientNode,
    contract: Contract,
    amount: int,
    sender: str,
    recipient: str,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call:
        print(f"Submitting transfer request for {amount} to {recipient}")

    enc_amount = encrypt_single(
        client.cryptosystem, client.network_encryption_key, amount
    )
    ser_amount = serialize_single(client.cryptosystem, enc_amount)
    if first_call:
        print(f"Serialized Encrypted Amount: {ser_amount.hex()}")
    try:
        tx_hash = contract.functions.transfer(recipient, ser_amount).transact(
            {"from": sender, "value": Wei(TRANSFER_FUNC_PAYMENT)}
        )
        sleep_after_transcation()
        print("Transfer request submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit transfer request: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying transfer request")
            submit_transfer_request(
                w3, client, contract, amount, sender, recipient, False
            )
        else:
            print("Transfer request cancelled")
            return


def submit_key_registration_request(
    w3: Web3,
    contract: Contract,
    sender: str,
    public_key: bytes,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call and mode == Mode.TEST:
        print(
            f"Submitting key registration request for {sender} with public key {public_key.hex()}"
        )
    try:
        tx_hash = contract.functions.registerKey(public_key).transact(
            {"from": sender, "value": Wei(REGISTER_KEY_FUNC_PAYMENT)}
        )
        sleep_after_transcation()
        print("Key registration request submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit key registration request: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying key registration request")
            submit_key_registration_request(w3, contract, sender, public_key, False)
        else:
            print("Key registration request cancelled")
            return


def submit_balance_update_request(
    w3: Web3,
    contract: Contract,
    sender: str,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call:
        print(f"Submitting encrypted balance sync request for {sender}")
    try:
        tx_hash = contract.functions.updateEncryptedBalance().transact(
            {"from": sender, "value": Wei(UPDATE_ENCRYPTED_BALANCE_FUNC_PAYMENT)}
        )
        sleep_after_transcation()
        print("Encrypted Balance sync request submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit encrypted balance sync request: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying encrypted balance sync request")
            submit_balance_update_request(w3, contract, sender, False)
        else:
            print("Encrypted Balance sync request cancelled")
            return


def submit_balance_reencryption_request(
    w3: Web3,
    contract: Contract,
    sender: str,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> None:
    if first_call:
        print(f"Submitting balance reencryption sync request for {sender}")
    try:
        tx_hash = contract.functions.updateReencryptedBalance().transact(
            {"from": sender, "value": Wei(UPDATE_REENCRYPTED_BALANCE_FUNC_PAYMENT)}
        )
        sleep_after_transcation()
        print("Balance reencryption sync request submitted")
        print(f"Transaction hash: 0x{tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 1:
            print("Transaction successful")
        else:
            print("Transaction failed")
            raise ValueError("Transaction failed")
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to submit balance reencryption sync request: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying balance reencryption sync request")
            submit_balance_reencryption_request(w3, contract, sender, False)
        else:
            print("Balance reencryption sync request cancelled")
            return


def get_balance(
    contract: Contract,
    account: str,
    client_node: CPUCryptoSystemClientNode,
    esk: bytes,
    first_call: bool = True,
    mode: Mode = Mode.CLI_APP,
) -> int:
    if first_call:
        print(f"Getting reencrypted balance for {account}\n")

    try:
        ser_enc_bal = contract.functions.encrypted_balances(account).call(
            {"from": account}
        )
        while len(ser_enc_bal) == 0:
            sleep_after_transaction_failure()
            user_input = input(
                "No encrypted balance found. Do you want to try again? (y/n): "
            )
            if user_input.lower() != "n":
                print("Retrying get balance")
                ser_enc_bal = contract.functions.encrypted_balances(account).call(
                    {"from": account}
                )
            else:
                print("Get balance request cancelled")
                return -1
        if len(ser_enc_bal) == 0:
            raise ValueError("No encrypted balance found")

        renc_bal = contract.functions.reencrypted_balances(account).call(
            {"from": account}
        )

        while len(renc_bal) == 0:
            sleep_after_transaction_failure()
            user_input = input(
                "No reencrypted balance found. Do you want to try again? (y/n): "
            )
            if user_input.lower() != "n":
                print("Retrying get balance")
                renc_bal = contract.functions.reencrypted_balances(account).call(
                    {"from": account}
                )
            else:
                print("Get balance request cancelled")
                return -1

        if len(renc_bal) == 0:
            raise ValueError("No reencrypted balance found")

        enc_bal = deserialize_single(client_node.cryptosystem, ser_enc_bal)
        print(f"Encrypted balance: {ser_enc_bal.hex()}\n")
        print(f"Reencrypted balance: {renc_bal.hex()}\n")
        reencryptor = client_node.reencryptor
        plaintext = reencryptor.decrypt(renc_bal, enc_bal, esk)
        int_bal = int(client_node.cryptosystem.get_float_from_plaintext(plaintext))
        if mode != Mode.CLI_APP:
            print(f"Decrypted balance: {int_bal}")
        return int_bal
    except Exception as e:
        sleep_after_transaction_failure()
        print(f"Failed to get balance: {e}")
        user_input = input("Do you want to try again? (y/n): ")
        if user_input.lower() != "n":
            print("Retrying get balance")
            return get_balance(contract, account, client_node, esk, False)
        else:
            print("Get balance request cancelled")
            return -1


def test_mint(
    w3: Web3,
    client: CPUCryptoSystemClientNode,
    contract: Contract,
    sender_priv_key: str,
    recipient_priv_key: str,
    sender_key: bytes,
    rec_key: bytes,
    balance_to_mint_sender: int,
    balance_to_mint_recipient: int,
    initial_balance_sender: int,
    initial_balance_recipient: int,
):
    sender = Account.from_key(sender_priv_key)
    recipient = Account.from_key(recipient_priv_key)
    set_middleware_and_default_account(w3, sender_priv_key)
    submit_mint_request(
        w3, client, contract, balance_to_mint_sender, sender.address, sender.address
    )
    # print(f"Sleeping for {WAIT_BETWEEN_STEPS} seconds")
    sleep(WAIT_BETWEEN_STEPS)
    input(
        "Press Enter to continue after minting"
    )  # Wait for the user to confirm the minting
    set_middleware_and_default_account(w3, recipient_priv_key)
    submit_mint_request(
        w3,
        client,
        contract,
        balance_to_mint_recipient,
        recipient.address,
        recipient.address,
    )
    # print(f"Sleeping for {WAIT_BETWEEN_STEPS} seconds")
    sleep(WAIT_BETWEEN_STEPS)
    input(
        "Press Enter to continue after minting"
    )  # Wait for the user to confirm the minting
    set_middleware_and_default_account(w3, sender_priv_key)
    submit_balance_update_request(w3, contract, sender.address)
    submit_balance_reencryption_request(w3, contract, sender.address)
    # print(f"Sleeping for {WAIT_BETWEEN_STEPS} seconds")
    sleep(WAIT_BETWEEN_STEPS)
    set_middleware_and_default_account(w3, recipient_priv_key)
    submit_balance_update_request(w3, contract, recipient.address)
    submit_balance_reencryption_request(w3, contract, recipient.address)
    # print(f"Sleeping for {WAIT_BETWEEN_STEPS} seconds")
    sleep(WAIT_BETWEEN_STEPS)

    sleep(WAIT_BETWEEN_STEPS)
    input(
        "Press Enter to continue after balance update"
    )  # Wait for the user to confirm the balance update

    # Get balance and assert
    print("Asserting balance")
    set_middleware_and_default_account(w3, sender_priv_key)
    assert (
        get_balance(contract, sender.address, client, sender_key)
        == balance_to_mint_sender + initial_balance_sender
    )
    set_middleware_and_default_account(w3, recipient_priv_key)
    assert (
        get_balance(contract, recipient.address, client, rec_key)
        == balance_to_mint_recipient + initial_balance_recipient
    )


def test_transfer(
    w3: Web3,
    client: CPUCryptoSystemClientNode,
    contract: Contract,
    sender_priv_key: str,
    recipient_priv_key: str,
    sender_key: bytes,
    rec_key: bytes,
    transfer_amount: int,
    initial_balance_sender: int,
    initial_balance_recipient: int,
):
    sender = Account.from_key(sender_priv_key)
    recipient = Account.from_key(recipient_priv_key)
    set_middleware_and_default_account(w3, sender_priv_key)
    submit_transfer_request(
        w3, client, contract, transfer_amount, sender.address, recipient.address
    )
    # print(f"Sleeping for {WAIT_BETWEEN_STEPS} seconds")
    sleep(WAIT_BETWEEN_STEPS)
    input(
        "Press Enter to continue after transfer"
    )  # Wait for the user to confirm the transfer
    set_middleware_and_default_account(w3, sender_priv_key)
    submit_balance_update_request(w3, contract, sender.address)
    submit_balance_reencryption_request(w3, contract, sender.address)
    set_middleware_and_default_account(w3, recipient_priv_key)
    submit_balance_update_request(w3, contract, recipient.address)
    submit_balance_reencryption_request(w3, contract, recipient.address)
    # print(f"Sleeping for {WAIT_BETWEEN_STEPS} seconds")
    sleep(WAIT_BETWEEN_STEPS)

    input(
        "Press Enter to continue after balance update"
    )  # Wait for the user to confirm the balance update

    print("Asserting balance")
    if transfer_amount > initial_balance_sender:
        set_middleware_and_default_account(w3, sender_priv_key)
        assert (
            get_balance(contract, sender.address, client, sender_key)
            == initial_balance_sender
        )
        set_middleware_and_default_account(w3, recipient_priv_key)
        assert (
            get_balance(contract, recipient.address, client, rec_key)
            == initial_balance_recipient
        )
    else:
        set_middleware_and_default_account(w3, sender_priv_key)
        assert (
            get_balance(contract, sender.address, client, sender_key)
            == initial_balance_sender - transfer_amount
        )
        set_middleware_and_default_account(w3, recipient_priv_key)
        assert (
            get_balance(contract, recipient.address, client, rec_key)
            == initial_balance_recipient + transfer_amount
        )


def test(config_path: str):
    print("Running test")
    w3, client, contract, ov_token_contract, sender_priv_key, recipient_priv_key = (
        setup(config_path, Mode.TEST)
    )
    sender_key_pair = client.reencryptor.generate_serialized_key_pair()
    rec_key_pair = client.reencryptor.generate_serialized_key_pair()
    sender = Account.from_key(sender_priv_key)
    recipient = Account.from_key(recipient_priv_key)
    set_middleware_and_default_account(w3, sender_priv_key)
    submit_key_registration_request(w3, contract, sender.address, sender_key_pair[1])
    set_middleware_and_default_account(w3, recipient_priv_key)
    submit_key_registration_request(w3, contract, recipient.address, rec_key_pair[1])
    # print(f"Sleeping for {WAIT_BETWEEN_STEPS} seconds")
    sleep(WAIT_BETWEEN_STEPS)
    test_mint(
        w3,
        client,
        contract,
        sender_priv_key,
        recipient_priv_key,
        sender_key_pair[0],
        rec_key_pair[0],
        100,
        45,
        0,
        0,
    )
    test_transfer(
        w3,
        client,
        contract,
        sender_priv_key,
        recipient_priv_key,
        sender_key_pair[0],
        rec_key_pair[0],
        90,
        100,
        45,
    )


def save_key(priv_key: bytes, pub_key: bytes) -> None:
    with open("rsa_private_key.txt", "wb") as f:
        f.write(priv_key)
    print("Private key saved to private_key.txt")
    with open("rsa_public_key.txt", "wb") as f:
        f.write(pub_key)
    print("Public key saved to public_key.txt")
    print("Add the following lines to the config file:")
    print(f"\"rsa_private_key_path\": \"{os.path.abspath('rsa_private_key.txt')}\",")
    print(f"\"rsa_public_key_path\": \"{os.path.abspath('rsa_public_key.txt')}\"")


def load_key(priv_key_file: str, pub_key_file: str) -> Tuple[bytes, bytes]:
    priv_key: bytes = b""
    try:
        with open(priv_key_file, "rb") as f:
            priv_key = f.read()
        print("Private key loaded from private_key.txt")
    except FileNotFoundError:
        print(
            "Private key file not found, please register the keys, otherwise you wont be able to decrypt the balance"
        )

    pub_key: bytes = b""
    try:
        with open(pub_key_file, "rb") as f:
            pub_key = f.read()
        print("Public key loaded from public_key.txt")
    except FileNotFoundError:
        print(
            "Public key file not found, please re-register the keys, otherwise you wont be able to encrypt the balance"
        )

    return priv_key, pub_key


def cli_app(config_path: str):
    print("Running CLI app")
    w3, client, contract, ov_token_contract, priv_key, _ = setup(
        config_path, Mode.CLI_APP
    )
    set_middleware_and_default_account(w3, priv_key)
    account = Account.from_key(priv_key)
    address = account.address
    config = load_config(config_path, Mode.CLI_APP)
    rsa_priv_key: bytes = b""
    rsa_pub_key: bytes = b""
    if config.rsa_private_key_path and config.rsa_public_key_path:
        rsa_priv_key, rsa_pub_key = load_key(
            config.rsa_private_key_path, config.rsa_public_key_path
        )
    else:
        print(
            "Reencryption keys not found. Please use the register option to generate and register keys."
        )
    conversion_rate = get_conversion_rate(contract)
    print(f"OV token conversion rate: {conversion_rate[0]}")
    print(f"ETH conversion rate: {conversion_rate[1]}")

    while True:
        print("\nMenu:")
        print("0. Register")
        print("1. Mint")
        print("2. Transfer")
        print("3. Fetch balance")
        print("4. OV Token Options")
        print("5. Fetch eth balance")
        print("6. Fetch network details")
        print("7. Exit")
        choice = input("Enter your choice: ")
        print("")
        if choice == "0":
            rsa_priv_key, rsa_pub_key = (
                client.reencryptor.generate_serialized_key_pair()
            )
            save_key(rsa_priv_key, rsa_pub_key)
            print("\nRegistering keys...\n")
            submit_key_registration_request(
                w3, contract, address, rsa_pub_key, True, Mode.CLI_APP
            )
        elif choice == "1":
            print("\nMint Menu:")
            print("0. Mint for free")
            print("1. Mint with OV token")
            print("2. Mint with ETH")
            mint_choice = input("Enter your choice: ")
            amount = int(input("Enter amount to mint: "))
            if mint_choice == "0":
                submit_mint_request(
                    w3, client, contract, amount, address, address, True, Mode.CLI_APP
                )
            elif mint_choice == "1":
                print(f"OV Token conversion rate: {conversion_rate[0]}")
                print("Make sure you have approved the OV token contract")
                submit_mint_with_ov_token_request(
                    w3,
                    contract,
                    ov_token_contract,
                    amount,
                    address,
                    address,
                    True,
                    Mode.CLI_APP,
                )
            elif mint_choice == "2":
                print(f"ETH conversion rate: {conversion_rate[1]}")
                print(
                    "Make sure you have enough ETH in your account to pay for the transaction"
                )
                submit_mint_with_eth_request(
                    w3,
                    contract,
                    amount,
                    address,
                    address,
                    conversion_rate[1],
                    True,
                    Mode.CLI_APP,
                )
            else:
                print("Invalid choice")
                print("Please try again")
                continue
        elif choice == "2":
            recipient = input("Enter recipient address: ")
            amount = int(input("Enter amount to transfer: "))
            submit_transfer_request(
                w3, client, contract, amount, address, recipient, True, Mode.CLI_APP
            )
        elif choice == "3":
            if rsa_priv_key == b"" or rsa_pub_key == b"":
                print(
                    "Reencryption keys not found. Please first register new keys to fetch balance."
                )
                continue
            print("Fetching balance...")
            submit_balance_update_request(w3, contract, address, True, Mode.CLI_APP)
            submit_balance_reencryption_request(
                w3, contract, address, True, Mode.CLI_APP
            )
            sleep_after_transcation()
            balance = get_balance(
                contract, address, client, rsa_priv_key, True, Mode.CLI_APP
            )
            print(f"Fetched balance: {balance}")
        elif choice == "4":
            print("\nOV Token Menu:")
            print("0. Mint OV Token")
            print("1. Approve OV Token")
            print("2. Fetch OV Token Balance")
            ov_token_choice = input("Enter your choice: ")
            if ov_token_choice == "0":
                amount = int(input("Enter amount to mint: "))
                submit_ov_token_mint_request(
                    w3,
                    ov_token_contract,
                    address,
                    address,
                    amount,
                    True,
                    Mode.CLI_APP,
                )
            elif ov_token_choice == "1":
                amount = int(input("Enter amount to approve: "))
                submit_ov_token_approve_request(
                    w3, ov_token_contract, address, config.contract_address , amount, True, Mode.CLI_APP
                )
            elif ov_token_choice == "2":
                balance = get_ov_token_balance(
                    w3, ov_token_contract, address, True, Mode.CLI_APP
                )
                print(f"OV Token balance: {balance}")
            else:
                print("Invalid choice")
                print("Please try again")
                continue
        elif choice == "5":
            print("Fetching ETH balance...")
            balance = get_eth_balance(w3, address, True, Mode.CLI_APP)
            print(f"Fetched ETH balance: {balance}")
        elif choice == "6":
            print("Fetching network details...")
            nd = get_network_details(config.openvector_relayer_endpoint_url)
            print(f"Network details: {nd}")
        elif choice == "7":
            print("Exiting...")
            break
        else:
            print("Invalid choice")
            print("Please try again")


@dataclass(frozen=True, slots=True)
class CliArgs:
    config_file_path: str
    mode: Mode = Mode.CLI_APP


def parse_args():
    parser = argparse.ArgumentParser(description="Run the client network")
    parser.add_argument("config", type=str, help="Path to the config file")
    parser.add_argument(
        "--mode",
        type=str,
        choices=[mode.value for mode in Mode],
        default=Mode.CLI_APP.value,
        help="Mode of operation (test, cli_app)",
    )
    args = parser.parse_args()
    return CliArgs(config_file_path=args.config, mode=Mode(args.mode))


def main():
    args = parse_args()
    if args.mode == Mode.TEST:
        test(args.config_file_path)
    else:
        cli_app(args.config_file_path)


if __name__ == "__main__":
    main()
