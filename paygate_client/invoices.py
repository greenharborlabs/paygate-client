"""Small BOLT11 helpers used before submitting payments."""

from __future__ import annotations

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_VALUES = {char: index for index, char in enumerate(_BECH32_CHARSET)}
_MSAT_PER_BTC = 100_000_000_000
_MSAT_MULTIPLIERS = {
    "m": 100_000_000,
    "u": 100_000,
    "n": 100,
    "p": 1,
}


def payment_hash_from_invoice(bolt11: str) -> str | None:
    decoded = _bech32_data_without_checksum(bolt11)
    if decoded is None or len(decoded) < 7:
        return None

    index = 7
    while index + 3 <= len(decoded):
        tag = decoded[index]
        data_length = (decoded[index + 1] << 5) + decoded[index + 2]
        data_start = index + 3
        data_end = data_start + data_length
        if data_end > len(decoded):
            return None
        if _BECH32_CHARSET[tag] == "p" and data_length == 52:
            converted = _convert_bits(decoded[data_start:data_end], 5, 8, pad=False)
            if converted is None or len(converted) != 32:
                return None
            return bytes(converted).hex()
        index = data_end
    return None


def amount_sats_from_invoice(bolt11: str) -> int | None:
    hrp = _hrp(bolt11)
    if hrp is None or not hrp.startswith("ln"):
        return None

    amount_part = _amount_part(hrp[2:])
    if amount_part is None:
        return None

    suffix = amount_part[-1]
    if suffix.isalpha():
        raw_amount = amount_part[:-1]
        multiplier = _MSAT_MULTIPLIERS.get(suffix)
        if multiplier is None:
            return None
    else:
        raw_amount = amount_part
        multiplier = _MSAT_PER_BTC

    if not raw_amount.isdigit():
        return None

    msats = int(raw_amount) * multiplier
    return (msats + 999) // 1000


def _hrp(bolt11: str) -> str | None:
    if bolt11.lower() != bolt11 and bolt11.upper() != bolt11:
        return None
    normalized = bolt11.lower()
    separator = normalized.rfind("1")
    if separator < 1:
        return None
    return normalized[:separator]


def _amount_part(currency_and_amount: str) -> str | None:
    index = 0
    while index < len(currency_and_amount) and currency_and_amount[index].isalpha():
        index += 1
    if index == len(currency_and_amount):
        return None
    return currency_and_amount[index:]


def _bech32_data_without_checksum(bolt11: str) -> list[int] | None:
    if bolt11.lower() != bolt11 and bolt11.upper() != bolt11:
        return None
    normalized = bolt11.lower()
    separator = normalized.rfind("1")
    if separator < 1 or separator + 7 > len(normalized):
        return None
    data_chars = normalized[separator + 1 :]
    try:
        data = [_BECH32_VALUES[char] for char in data_chars]
    except KeyError:
        return None
    return data[:-6]


def _convert_bits(
    data: list[int],
    from_bits: int,
    to_bits: int,
    *,
    pad: bool,
) -> list[int] | None:
    accumulator = 0
    bits = 0
    result: list[int] = []
    max_value = (1 << to_bits) - 1
    max_accumulator = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            return None
        accumulator = ((accumulator << from_bits) | value) & max_accumulator
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & max_value)
    elif bits >= from_bits or ((accumulator << (to_bits - bits)) & max_value):
        return None
    return result
