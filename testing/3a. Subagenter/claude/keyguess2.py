#!/usr/bin/env python3
from base64 import b64decode
from Crypto.Cipher import AES

def make_key(s): return s.encode().ljust(16, b"\x00")[:16]

def dec(key, b64s):
    raw = b64decode(b64s)
    pt = AES.new(key, AES.MODE_ECB).decrypt(raw[1:])
    p = pt[-1]
    if 1 <= p <= 16 and pt[-p:] == bytes([p]) * p:
        pt = pt[:-p]
    return raw[0], pt

samples = [
    ("17:47:19.876 108B", "ARoJrzWVL26gH6JkZPvbjR8f/JXr+BEV2DYhNDI5mC2ACh9fiSNXkLE2Rm8DeVkwhrtIUmwjESAsDafhn1qhgzeX9XL12LW9ZEFnxNOtGUEp"),
    ("17:47:19.884 364B", "AUZeHlsmI5Pcj5jef7mCEz/+DbQYamj4SBVVsZrg8kgDMj6dLuJvFJG+wkm9LVbJH9l8sUY3R2Y2bgKJaozJ5SJZODTwD5kL5Kz6v68AfDLTcqoe9IQ9/2IZyJ3U/rP3IY3wYrmGjMuqFdF4H4GTvso9cWLvHrDzJrKZ0GPvClrb9G75O5jX/jfYDh/nRx20lKqqso0fU6wgtev79tVFFQEopiXRX7YNtrcx4F7xtb/4EQDuRe/AtKnGTFT9/7KhFY/jwe/xE3y9D1IxaBjqqf1DTkewNzBEMkVBWrtPaXfVEYq6h0ZtpoP0GiZsfxD7LqWvKaGtViwzzmeulE7YGugFJccN+BHL4MHb5Cx2pvan"),
    ("17:47:28.848 44B  (heartbeat-A)", "Aft8mr3RJ6zjFR66w+mTbjPVEvZzp4/vdYDYr99GtQFK"),
    ("17:48:38.885 108B", "ASeH65dxp8DD3b6Isp9qgRD3JTcZMmeEe0htxuTc42xYxA2BOip/PbVdxas1oyyqbU6ZaLYzWzBReYG23WV3f4DBtCMxbrpy5EHXh+80TgHa"),
    ("17:48:43.048 172B", "AVlw6Ht/Fy8oQtjq85m5uGgMVvN4HIAtc6lihFU3g2kvRU+Q37iz9R8QZJClpBUUM9yXkt4ha98f4GPPWLSDZpSf+n0qdiQ6PrpS4jgQ10ZVaelDHq2o7BDDEh5k6OT22aEn6jUeBXjZzexIA0P/uVWx8RQH6LG1gXEUhCeikpFL"),
    ("17:48:43.307 172B", "AWaiQirac3bM8V10m/qC2vKWR83tE5Ay/hFTbL8DZ/goQWaJMQPZ9OB0uIim7Vgz9APTsjAb/4uFoLzvzlk+AmPzK+gkRhYW4Pv0GNrd7Nv2UKc+XHIWfn2/k3eeymgMRVtGAjnlHFJC21w9e1FxopIpf6FLal/UAen2/RPB6Xon"),
    ("17:51:10.657 172B", "AVj+t0qXdFqhK/Jyr6+dYZpjBTQwRDEVSY85ZQENiEGdrOw7Sk+MSj+r0ex927Z4ceApzSLp3TqYiVZQZktylxf+M2Z4yn8I+UiqM+xeAcPd6/qxrQaK+g03tXyGF2a+fXOHaVq3DiDac77MBvG5+lULKT4DzrNTm02ujyiaR5AL"),
    ("17:51:51.197 108B", "ARoJrzWVL26gH6JkZPvbjR9OHPIksjXBLhknUEhQfSwjCh9fiSNXkLE2Rm8DeVkwhrtIUmwjESAsDafhn1qhgzeX9XL12LW9ZEFnxNOtGUEp"),
    ("17:52:04.789 44B  (heartbeat-B)", "AXIx72xiqcdTMEm1aaAZHeHb+f2Xt3/ETpvr8yRD0W52"),
    ("17:52:04.801 108B", "Ad4ukxJjWmNhuI26pdzK4yzUAouDsc6xO3FkrQEj+kwAUKc+XHIWfn2/k3eeymgMRVtGAjnlHFJC21w9e1FxopIpf6FLal/UAen2/RPB6Xon"),
    ("17:52:28.531 68B", "Ad+sRg5iheHwavgKVsDfsjWrNLOFgPZFqdbBdYGi8AWuEYN3CGNxgtN7gS0LCc9/hg=="),
    ("17:52:28.537 44B  (heartbeat-C)", "AWNj68g2XGLbMzyGJ7gMxoPrQMDq6VQlnFynUWlrQpqp"),
    ("17:52:32.469 132B", "AUa09AjdA3jkt8dr1npHPnYRGV1vK2RYfGko7P+AJkr9TPm/PJ8nRBZJcTEtkSErHAI3A9uhaAEmL8E/OdCWn7F4W77U6B316+E7EzZmtPkoLY+ok4CviPVGT94JEuOfkg=="),
    ("17:52:40.387 556B", "AUdGz12wy0suSXCncEyqOO5cFEC/80wWqrGnvdS0qUlFS/lJesfRygU69S8PQnFmbxAuqQxxq2a5SLoAj47t0/MOYyOvkSMZL4MZEsPfdE9PqiwGVtFdL++a3YGxa19c0lXlAxlP6+ypiC2SuokxCT5zOU4UabC/FxuOBHMhuEECVX4hdopohJZ6vYkcCMamxXUQixY1baxc0JzY/NiQbsavzllV/qCPpvr999yUNNX8AcijUrymsxJK0ODA0j0ji4MnWJvivfrwJeA3LRToxIf9o3abjlpZeRCLXTxLd4LekBeyIEzS2LZVqvMqXKUziEmt1v6Bu7D9zwQ5BfYP34U1cD6bAyy82bQSB8kOXBS6rX30KeG8jZxYV/1p3Sm08bfXCSAI6DYTCj3piDtxg21SmtP4jjapxBxqrYq2RICutCoDZVyaqWLtOWKvtkm+jP4NCQY9DrVPiRxGMQEOFl3YMbkLQEzwgPXvMLLmeN9l42mCabsN0K8KuCyt7K0gnOM6mqkRNYmLrFfhkG4fSJm1M5/nxqB3mO851f5jUdKG"),
]

for keyguess in ["anders", "Anders", "ANDERS", "anders\n"]:
    key = make_key(keyguess)
    print(f"\n===== KEY = {keyguess!r} -> {key!r} =====")
    for label, b in samples[:3]:
        tag, pt = dec(key, b)
        printable = sum(32 <= x < 127 or x in (9, 10, 13) for x in pt)
        print(f"  [{label}] type=0x{tag:02x} printable={printable}/{len(pt)} -> {pt[:80]!r}")
