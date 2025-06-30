import asyncio, aiohttp, os
from web3 import Web3
from solana.rpc.async_api import AsyncClient
from solana.publickey import PublicKey
from sklearn.ensemble import RandomForestClassifier
import joblib

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

MIN_LIQUIDITY = 1000
MAX_MARKETCAP = 200_000

DEX_API = "https://api.dexscreener.io/latest/dex/pairs"
RAYDIUM_API = "https://api.dexscreener.io/latest/dex/pairs/solana"
HONEYPOT_API = "https://api.honeypot.is/v1/IsHoneypot"
CHAINS = {
    "Ethereum": "eth",
    "Base": "base",
    "Solana": "solana"
}

RPCS = {
    "Ethereum": Web3.HTTPProvider("https://cloudflare-eth.com"),
    "Base": Web3.HTTPProvider("https://mainnet.base.org")
}

w3_instances = {c: Web3(rpc) for c, rpc in RPCS.items() if c != "Solana"}
solana_client = AsyncClient("https://api.mainnet-beta.solana.com")
seen = set()

model_path = "ml_model.pkl"
if os.path.exists(model_path):
    ml_model = joblib.load(model_path)
else:
    ml_model = None

async def fetch_pairs(session, chain_key):
    try:
        resp = await session.get(f"{DEX_API}/{chain_key}", timeout=10)
        return (await resp.json()).get("pairs", [])
    except:
        return []

async def honeypot_check(session, address):
    try:
        res = await session.post(HONEYPOT_API, json={"address": address})
        return res.ok and not (await res.json())["honeypotResult"]["isHoneypot"]
    except:
        return False

def owner_renounced(web3, contract_address):
    abi = [{"constant": True, "inputs": [], "name": "owner", "outputs": [{"name": "", "type": "address"}], "type": "function"}]
    try:
        owner = web3.eth.contract(contract_address, abi=abi).functions.owner().call()
        return owner in ("0x0000000000000000000000000000000000000000", "0x")
    except:
        return False

def ml_token_score(token):
    if not ml_model:
        return True
    features = [
        token.get("liquidity", {}).get("usd", 0),
        token.get("fdv", 0),
        len(token["baseToken"].get("name", "")),
        len(token["baseToken"].get("symbol", ""))
    ]
    try:
        return ml_model.predict([features])[0] == 1
    except:
        return False

async def send_alert(session, token, chain):
    text = (
        f"🚨 *New Safe Token Detected*\n"
        f"Chain: {chain}\n"
        f"Name: {token['baseToken']['name']}\n"
        f"Symbol: {token['baseToken']['symbol']}\n"
        f"Liquidity: ${token['liquidity']['usd']:.0f}\n"
        f"Market Cap: ${token.get('fdv', 0):,}\n"
        f"Contract: `{token['pairAddress']}`\n"
        f"[View Chart]({token['url']})"
    )
    await session.post(
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
        json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"}
    )

async def check_chain(session, chain, key):
    tokens = await fetch_pairs(session, key)
    for token in tokens:
        address = token.get("pairAddress")
        if not address or address in seen:
            continue
        liq = token.get("liquidity", {}).get("usd", 0)
        mc = token.get("fdv", 0) or 0
        if liq < MIN_LIQUIDITY or mc > MAX_MARKETCAP:
            continue
        if chain != "Solana" and not await honeypot_check(session, address):
            continue
        if chain != "Solana":
            token_addr = Web3.toChecksumAddress(token["baseToken"]["address"])
            web3 = w3_instances[chain]
            if not owner_renounced(web3, token_addr):
                continue
        if not ml_token_score(token):
            continue
        await send_alert(session, token, chain)
        seen.add(address)

async def main():
    async with aiohttp.ClientSession() as session:
        while True:
            for chain, key in CHAINS.items():
                await check_chain(session, chain, key)
            await asyncio.sleep(15)

if __name__ == "__main__":
    asyncio.run(main())
