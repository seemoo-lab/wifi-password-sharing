# Apple Wi-Fi Password Sharing

A hacky implementation of Apple's Wi-Fi Password Sharing protocol for macOS.

A Linux-only implementation in Python is available [here](https://github.com/seemoo-lab/openwifipass).

## Disclaimer

This project contains experimental software and is the result of reverse engineering efforts by the [Open Wireless Link](https://owlink.org) project.
The code serves solely documentary and educational purposes. It is *untested* and *incomplete*.
This project is not affiliated with or endorsed by Apple Inc.

## Requirements

Install [`libsodium`](https://doc.libsodium.org), e.g., via Homebrew:

```bash
brew install libsodium
```

## Run

We provide both the grantor and requestor roles.

### Grantor

Run the target `PWS-Grantor` to start a password sharing giving device client, which will scan BLE advertisements and connect to the first matching one and start sharing. Alternatively, from the command line:

```bash
./PWS-Grantor <ssid> <psk>
```

### Requestor

The requestor role requires a special setup due to security and Bluetooth restrictions of macOS.

**Step 1:** We need to disable the AMFI security feature to access the user's Apple ID certificate [as described here](https://github.com/seemoo-lab/airdrop-keychain-extractor). Reboot in recovery mode (⌘+R) and run:

```bash
csrutil disable
nvram boot-args="amfi_get_out_of_my_way=0x1"
```

**Step 2:** Since we can not set the manufacturer data of a BLE advertisement with `CoreBluetooth`, we provide a GATT relay server in [`python-gatt-relay`](python-gatt-relay). Setup the relay on an external Linux machine, e.g., a Raspberry Pi 4. See the included [`README`](python-gatt-relay/README.md) for details.

**Step 3:** Finally, run the `PWS-Requestor` target to ask for a password from another device. Alternatively, from the command line:

```bash
./PWS-Requestor <appleID> <gattServerAddress>
```

## Authors

* Jannik Lorenz

## Publications

* Milan Stute, Alexander Heinrich, Jannik Lorenz, and Matthias Hollick. **Disrupting Continuity of Apple’s Wireless Ecosystem Security: New Tracking, DoS, and MitM Attacks on iOS and macOS Through Bluetooth Low Energy, AWDL, and Wi-Fi.** *30th USENIX Security Symposium (USENIX Security ’21)*, August 11–13, 2021, Vancouver, B.C., Canada. *To appear*.
* Jannik Lorenz. **Wi-Fi Sharing for All: Reverse Engineering and Breaking the Apple Wi-Fi Password Sharing Protocol.** Bachelor thesis, *Technical University of Darmstadt*, March 2020.
