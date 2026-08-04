# Network / WLAN / DNS

## What network evidence the app supports

The `network` family covers local evidence of connectivity and network configuration on Windows with a cautious approach:

- WLAN profiles (`Wlansvc` XML)
- `Microsoft-Windows-WLAN-AutoConfig/Operational` events already parsed by EVTX
- Registry/RECmd outputs related to `NetworkList` and `Tcpip\\Parameters\\Interfaces`
- `hosts` file
- DNS cache/config in CSV/JSON
- `ipconfig`, `netsh wlan`, `netstat`, and `arp` outputs in TXT

An isolated indicator is not interpreted as proof of malicious activity. The priority is to contextualize connectivity, Wi-Fi profiles, DNS/hosts, and correlations with other evidence.

## What is parsed directly from Velociraptor

Discovery detects and can selectively extract:

- `ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/*/*.xml`
- `Windows/System32/drivers/etc/hosts`
- `*DNSCache*.csv/json`
- `*ipconfig*.txt`
- `*netsh*.txt`
- `*netstat*.txt`
- `*arp*.txt`
- `NetAdapter`, `NetIPConfiguration`, `NetRoute`, `NetTCPConnection`, `NetUDPEndpoint` outputs when present

It also detects:

- `Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx` as `handled_by_evtx_parser`
- related `SOFTWARE`, `SYSTEM`, and `NTUSER.DAT` hives as `discovery_only` or `detected_not_implemented` candidates if there is no raw parser

## What remains as discovery

The following remain as discovery or depend on another parser:

- raw WLAN EVTX if only the `.evtx` exists and not the parsed CSV
- raw `SOFTWARE` / `SYSTEM` / `NTUSER.DAT` hives
- network inventory derived from generic outputs not yet supported

This means the app preserves the evidence and shows it in the UI, but must not present it as parsed if a specific parser doesn't exist yet.

## WLAN profiles

The WLAN XML parser extracts:

- `SSID`
- profile name
- `connectionType`
- `connectionMode`
- authentication
- encryption
- key type
- whether `keyMaterial` exists
- MAC randomization hints

WLAN profiles are normalized as:

- `artifact.type = network`
- `event.type = wlan_profile`
- `event.action = wlan_profile_observed`

### What SSID / auth / encryption / keyMaterial mean

- `SSID`: name of the Wi-Fi network observed in the profile
- `authentication`: type of authentication, e.g. `WPA2PSK`, `open`
- `encryption`: encryption, e.g. `AES`, `TKIP`, `none`
- `keyMaterial`: indicates the profile contained key material

### Why Wi-Fi keys are not shown in plaintext

If `keyMaterial` is present, the app:

- sets `wlan.key_material_present = true`
- adds `wlan_key_material_present`
- redacts the value (`[REDACTED]`)
- does not include it in `search_text`
- does not summarize it in `raw_summary`

This prevents leaking secrets in search, timeline, or detail panels.

## NetworkList / TCPIP registry

`NetworkList` keys provide:

- network profile names
- GUIDs
- network category
- `last_write` timestamps useful as context

`Tcpip\\Parameters\\Interfaces` keys provide:

- IPs
- gateways
- DNS servers
- DHCP
- domain/suffix if present

The app normalizes this as:

- `network_profile`
- `interface_config`
- `dns_config`

but still preserves `registry.*` so the analyst can see the original key and value.

## DNS cache / config

The DNS parser supports generic CSV/JSON with fields such as:

- `Name`
- `Domain`
- `Type`
- `Data`
- `IPAddress`
- `TTL`
- `Server`
- `Interface`

This is useful to answer:

- which domains or DNS entries were observed
- which DNS server was configured
- whether the indicator matches Browser, BITS, PowerShell, Defender, or Cloud

### DNS limitations

- the DNS cache may not exist after reboot
- the format depends heavily on the source
- an observed domain does not by itself imply browsing or malware

## Hosts file

The parser:

- ignores comments and blank lines
- supports multiple hostnames per line
- creates `hosts_entry` events

What to look for:

- redirects to `127.0.0.1` or `0.0.0.0`
- Microsoft, Defender, cloud, or security domains being redirected
- uncommented, non-standard overrides

An entry in `hosts` is not automatically malicious, but it gains a lot of value if it correlates with Browser, Defender, BITS, or file changes in MFT.

## ipconfig / netsh / netstat / arp

### `ipconfig /all`

Allows extraction of:

- interface name
- description
- MAC
- IPv4 / IPv6
- gateway
- DNS servers
- DHCP server

### `netsh wlan`

Allows extraction of:

- Wi-Fi profiles
- profile names
- SSID hints
- authentication/encryption if included in the output

### `netstat`

Allows extraction of:

- protocol
- local address / port
- foreign address / port
- state
- PID if present

### `arp`

Allows extraction of:

- interface
- IP
- MAC
- type

These outputs are especially useful in live response, but they are also volatile: they describe a state observed at the moment of capture.

## Difference between observed indicator and malicious activity

The app distinguishes between:

- `network profile observed`
- `wlan profile observed`
- `wlan connection observed`
- `dns configuration observed`
- `hosts entry observed`
- `possible suspicious network configuration`
- `suspicious network activity candidate`

It does not assert C2, spoofing, intrusion, or malicious use just from seeing:

- an SSID
- a public DNS
- a normal entry in `hosts`
- a domain observed in DNS cache

## How it correlates with other evidence

### Browser

- DNS or `hosts` domain that matches web history
- `hosts` override affecting a visited domain

### BITS

- BITS remote domain or IP that matches DNS
- download near a WLAN connection or network change

### PowerShell

- URLs, domains, or IPs from commands that match DNS / netstat
- downloads or direct-IP connections

### Defender

- domains, resources, or paths related to observed network indicators

### Cloud Sync

- cloud domains like `onedrive.live.com`, `drive.google.com`, `dropbox.com`, `mega.nz`, `icloud.com`, `box.com`
- cloud activity near WLAN or DNS indicators

### SRUM

- bytes sent/received per application near Browser, BITS, or Cloud

### EVTX

- WLAN or process activity near other suspicious events

### MFT / USN

- changes to `hosts`
- modification of network artifacts or exported outputs

## Common false positives

- corporate or hotel WLAN profiles
- public DNS (`8.8.8.8`, `1.1.1.1`) used legitimately
- `hosts` entries for local development
- `netstat` outputs with administration or security software
- normal cloud domains observed by Browser or sync clients

## Limitations

- the DNS cache may not exist or may be incomplete
- a WLAN profile does not prove a recent connection
- `hosts` needs a timestamp and correlation to carry high weight
- `netstat` and `arp` are especially volatile when coming from live response
- BSSID, signal, and connection reason will not always be present
- the app must not infer Wi-Fi credentials or display them in plaintext

## Investigation examples

### 1. `hosts` override and affected browsing

1. See a suspicious `hosts_entry` for a Microsoft or security domain.
2. Correlate with Browser to check if that domain was visited.
3. Check MFT/USN to find out when the `hosts` file changed.

### 2. Open WLAN near suspicious activity

1. See a `wlan_profile` with `open` authentication.
2. Check nearby `wlan_connection` events in EVTX.
3. Correlate with Browser, BITS, or PowerShell in the same time window.

### 3. DNS / netstat and PowerShell

1. Observe a domain or direct IP in DNS or `netstat`.
2. Search for the same indicator in PowerShell and BITS.
3. If it also appears in Defender or SRUM, treat it as a strong correlation, not an isolated indicator.
