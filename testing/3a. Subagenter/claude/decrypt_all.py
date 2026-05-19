#!/usr/bin/env python3
"""Decrypt every distinct exfil/command body captured from the C2."""
from base64 import b64decode
from Crypto.Cipher import AES

KEY = b"ANDERS-DESKTOP".ljust(16, b"\x00")

def dec(b64s):
    raw = b64decode(b64s)
    tag = raw[0]
    pt = AES.new(KEY, AES.MODE_ECB).decrypt(raw[1:])
    p = pt[-1]
    if 1 <= p <= 16 and pt[-p:] == bytes([p]) * p:
        pt = pt[:-p]
    return tag, pt

def dec_cmd(b64s):
    pt = AES.new(KEY, AES.MODE_ECB).decrypt(b64decode(b64s))
    p = pt[-1]
    if 1 <= p <= 16 and pt[-p:] == bytes([p]) * p:
        pt = pt[:-p]
    return pt

# /update/servicedata (channel B - command output, type=3)
SERVICEDATA = [
    ("17:48:20.302  516B  (after dir Users)", "AzUJlQeZM3I+OVeM/d7PnXCFvL9agslfRp83+3sSG6bPoNDDL00/KlNiEHv6TnEkZDQpLkyl2ZBGrbyuFmQ2z499ml6qPyaSJz/yl5E4IMnBYabUZY4YD7il9Exb7BaGkCe9NGMqdq6Z9z1L0FYrL2aA3uSIQquRoX+6wI/FPPh7Jn/U5odqM32RI4PFV9glKpTrNzAm80PhL4ALTk7EZymBr0BRNopO4tb3S6NBXV5kpDqLlrLLwYq6lOBTmVF28Vo6cZldgecY4Y+IBEHC4vmNLO6IUGnDKKDz1EEb0q/L2+eVwxkGMVEEEdk5Fyirrys3o91HwNEWDwR6wW6ZERDSCiREAD7y9EQ/DiL92f+CvsuRYKCcyDLt6v1ZOemC3LEiuMkLgcbZcyctqQqnE7sWhbS3ZB+hBa9kGm6kavvayWjHDiYg7CsUJK22QOcdiUTUb6K4aaJ/BHsrTSLL/EhDOHu9sGFPuUirNu9BUWzDMtkpkf8FcXoJsaZrWTO5Qw=="),
    ("17:49:20.508  408B  (after dir Documents)", "AzUJlQeZM3I+OVeM/d7PnXCFvL9agslfRp83+3sSG6bPoNDDL00/KlNiEHv6TnEkZDQpLkyl2ZBGrbyuFmQ2z499ml6qPyaSJz/yl5E4IMnBxPl2ODIsOJBgIgH6A4vKOz6Vx6hF77S7sefCC4nRoWc7aE0Xt92yevlJOVPRHHi8GXx7+K8WufA/Xv2FPEQ7mXmWFrr2K7EbPNk/9oONC+crN6PdR8DRFg8EesFumREQBlqbSECeRcjSektwlFEEtsyWSXTpIZh/mlEZBPs8MnlZfTO8cSHUfIi42gH9Ak2vui188KQ6JNzPq3tPnIL9tw4w8lRSBXYi0FvXhMiw8E/Q+v25URrYP84wi8P5xEgBzGgOQ73wztXV/uD30wPCP+CZUMQEXin2yHYm+TnsTGE="),
    ("17:50:50.656  536B  (after dir Desktop)", "AzUJlQeZM3I+OVeM/d7PnXCFvL9agslfRp83+3sSG6bPoNDDL00/KlNiEHv6TnEkZDQpLkyl2ZBGrbyuFmQ2z499ml6qPyaSJz/yl5E4IMnBlQMadb+CWv1v4Sz3clNMLl3Ny7c4v6HupzF0JEsdiB2RLZRQOhXlPKzhE4iAdbtCwSv5cFq9GMtcyR19jcT1W0moj0cFmr6W+vUvND4a/t1aOnGZXYHnGOGPiARBwuL58C81C4jG1z2yd+mNdmR2YuBOclFX1YAKSZ52FFMbjF3UsYkfK3hrEYJaBiibfhg37711hJsU4wMnsIFnzDSegsSFCNb7l4ESWq+F6bgpfjaRLZRQOhXlPKzhE4iAdbtCCHMug8+KutNXPrNnwVgowSJIUxScrsr5SMeIZ17AEZpByDoo2nOAHV7ON4wDdR98lPb2HVgn2LPbdLQ7OLNynMQk0ydSk2+5pNtqCvQnwWNvqfj5vrAlUHfsPFLPHZWTBUj2SrO9EVUKMuROLN1rs/Ylz2miADfLOj1Mb9d4XPk="),
]

# /api/data (channel A - keylog/clipboard/window, type=1; cmd output via /api/data uses type=3 too)
APIDATA = [
    ("17:47:19.876  108B", "ARoJrzWVL26gH6JkZPvbjR8f/JXr+BEV2DYhNDI5mC2ACh9fiSNXkLE2Rm8DeVkwhrtIUmwjESAsDafhn1qhgzeX9XL12LW9ZEFnxNOtGUEp"),
    ("17:47:19.884  364B", "AUZeHlsmI5Pcj5jef7mCEz/+DbQYamj4SBVVsZrg8kgDMj6dLuJvFJG+wkm9LVbJH9l8sUY3R2Y2bgKJaozJ5SJZODTwD5kL5Kz6v68AfDLTcqoe9IQ9/2IZyJ3U/rP3IY3wYrmGjMuqFdF4H4GTvso9cWLvHrDzJrKZ0GPvClrb9G75O5jX/jfYDh/nRx20lKqqso0fU6wgtev79tVFFQEopiXRX7YNtrcx4F7xtb/4EQDuRe/AtKnGTFT9/7KhFY/jwe/xE3y9D1IxaBjqqf1DTkewNzBEMkVBWrtPaXfVEYq6h0ZtpoP0GiZsfxD7LqWvKaGtViwzzmeulE7YGugFJccN+BHL4MHb5Cx2pvan"),
    ("17:47:28.848  44B   (heartbeat)", "Aft8mr3RJ6zjFR66w+mTbjPVEvZzp4/vdYDYr99GtQFK"),
    ("17:48:38.885  108B", "ASeH65dxp8DD3b6Isp9qgRD3JTcZMmeEe0htxuTc42xYxA2BOip/PbVdxas1oyyqbU6ZaLYzWzBReYG23WV3f4DBtCMxbrpy5EHXh+80TgHa"),
    ("17:48:43.048  172B", "AVlw6Ht/Fy8oQtjq85m5uGgMVvN4HIAtc6lihFU3g2kvRU+Q37iz9R8QZJClpBUUM9yXkt4ha98f4GPPWLSDZpSf+n0qdiQ6PrpS4jgQ10ZVaelDHq2o7BDDEh5k6OT22aEn6jUeBXjZzexIA0P/uVWx8RQH6LG1gXEUhCeikpFL"),
    ("17:48:43.307  172B", "AWaiQirac3bM8V10m/qC2vKWR83tE5Ay/hFTbL8DZ/goQWaJMQPZ9OB0uIim7Vgz9APTsjAb/4uFoLzvzlk+AmPzK+gkRhYW4Pv0GNrd7Nv2UKc+XHIWfn2/k3eeymgMRVtGAjnlHFJC21w9e1FxopIpf6FLal/UAen2/RPB6Xon"),
    ("17:51:10.657  172B", "AVj+t0qXdFqhK/Jyr6+dYZpjBTQwRDEVSY85ZQENiEGdrOw7Sk+MSj+r0ex927Z4ceApzSLp3TqYiVZQZktylxf+M2Z4yn8I+UiqM+xeAcPd6/qxrQaK+g03tXyGF2a+fXOHaVq3DiDac77MBvG5+lULKT4DzrNTm02ujyiaR5AL"),
    ("17:51:51.197  108B", "ARoJrzWVL26gH6JkZPvbjR9OHPIksjXBLhknUEhQfSwjCh9fiSNXkLE2Rm8DeVkwhrtIUmwjESAsDafhn1qhgzeX9XL12LW9ZEFnxNOtGUEp"),
    ("17:52:04.789  44B   (heartbeat-2)", "AXIx72xiqcdTMEm1aaAZHeHb+f2Xt3/ETpvr8yRD0W52"),
    ("17:52:04.801  108B", "Ad4ukxJjWmNhuI26pdzK4yzUAouDsc6xO3FkrQEj+kwAUKc+XHIWfn2/k3eeymgMRVtGAjnlHFJC21w9e1FxopIpf6FLal/UAen2/RPB6Xon"),
    ("17:52:28.531  68B", "Ad+sRg5iheHwavgKVsDfsjWrNLOFgPZFqdbBdYGi8AWuEYN3CGNxgtN7gS0LCc9/hg=="),
    ("17:52:28.537  44B", "AWNj68g2XGLbMzyGJ7gMxoPrQMDq6VQlnFynUWlrQpqp"),
    ("17:52:32.469  132B", "AUa09AjdA3jkt8dr1npHPnYRGV1vK2RYfGko7P+AJkr9TPm/PJ8nRBZJcTEtkSErHAI3A9uhaAEmL8E/OdCWn7F4W77U6B316+E7EzZmtPkoLY+ok4CviPVGT94JEuOfkg=="),
    ("17:52:40.387  556B", "AUdGz12wy0suSXCncEyqOO5cFEC/80wWqrGnvdS0qUlFS/lJesfRygU69S8PQnFmbxAuqQxxq2a5SLoAj47t0/MOYyOvkSMZL4MZEsPfdE9PqiwGVtFdL++a3YGxa19c0lXlAxlP6+ypiC2SuokxCT5zOU4UabC/FxuOBHMhuEECVX4hdopohJZ6vYkcCMamxXUQixY1baxc0JzY/NiQbsavzllV/qCPpvr999yUNNX8AcijUrymsxJK0ODA0j0ji4MnWJvivfrwJeA3LRToxIf9o3abjlpZeRCLXTxLd4LekBeyIEzS2LZVqvMqXKUziEmt1v6Bu7D9zwQ5BfYP34U1cD6bAyy82bQSB8kOXBS6rX30KeG8jZxYV/1p3Sm08bfXCSAI6DYTCj3piDtxg21SmtP4jjapxBxqrYq2RICutCoDZVyaqWLtOWKvtkm+jP4NCQY9DrVPiRxGMQEOFl3YMbkLQEzwgPXvMLLmeN9l42mCabsN0K8KuCyt7K0gnOM6mqkRNYmLrFfhkG4fSJm1M5/nxqB3mO851f5jUdKG"),
]

CMDS = [
    ("17:48:20.010", "Q52aB5TFVA5uEM/IeZ0Kyg=="),
    ("17:49:20.346", "ISL6QPPTKg2tMQgQfCRu10uFvjw0koh/MudkA/oUS98="),
    ("17:50:50.567", "ISL6QPPTKg2tMQgQfCRu134S+r4B5p6X4HZo/X4d/vs="),
    ("17:51:50.695", "A45yK3lKmkrMpH01AxtchDAHsYTB95vlGUdgdYR6EekutR6WwKdtMbvDbfUfwsKt"),
]

print("====== C2 commands (operator -> implant via /windows/checkforupdate) ======")
for ts, b in CMDS:
    print(f"[{ts}] {dec_cmd(b)!r}")

print("\n====== /update/servicedata (command output, type=3) ======")
for label, b in SERVICEDATA:
    tag, pt = dec(b)
    print(f"[{label}] type=0x{tag:02x}\n{pt.decode('utf-8','replace')}\n---")

print("\n====== /api/data (keylog/clipboard/window/heartbeat) ======")
for label, b in APIDATA:
    tag, pt = dec(b)
    print(f"[{label}] type=0x{tag:02x}  -> {pt!r}")
