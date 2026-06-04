# Perimeter / VPN / firewall evidence recovered from host memory (2026-06-04)

Question: which machine holds VPN/firewall client or management software?
Answer: **admin (172.16.5.26)** is the network-management host (richest); **hunt
(172.16.5.25)** also qualifies. Both are MEMORY-ONLY (no disk) — evidence carved
from RAM.

## Management/VPN/log software present (memory string carve)

| Product | hunt | admin | Role |
|---|---|---|---|
| Palo Alto Panorama | 89 | 34 | firewall mgmt |
| Check Point SmartConsole | 6 | — | firewall mgmt |
| PuTTY / SecureCRT | 28 | 305 / 6 | SSH to network gear |
| NXLog / syslog-ng / Graylog / Splunk | 1 | 330/13/11/7 | log forwarding / SIEM |
| Cisco AnyConnect / GlobalProtect / OpenVPN | 8/6 | 5/–/12 | VPN clients |
| RADIUS / NPS (ias.exe) | 921/3 | 223 | VPN authentication |

## The big find: admin RAM captured a live SSH session (rsydow-a) into `base-fw`

`base-fw` = the **Linux perimeter firewall / VPN gateway**. Recovered from admin
memory (rsydow-a@base-fw shell + cat'd configs/logs):
- **OpenVPN server** in `/opt/vpnserver/` (iptables rules.20180808, rules.v4).
- **Squid proxy** (`base-proxy squid[...]`) logging internal web access.
- **NetFlow** capture (`nfcapd` / *.nfcapd) and a **Security Onion / Snort IDS**
  (`site-onion-sensor1 snort[...] ET DROP Dshield Block`).
- **Splunk forward** to external collector `155.6.3.6:9997`.
- Interfaces: eth1 = external/DMZ, eth2/eth3 = internal. DMZ segment = 172.16.10.x
  (FTP .12, DNS .11, SMTP/mail relay .10).

## 192.168.30.0/24 = the OpenVPN client pool (confirms the ingress vector)

IPs clustered with the VPN/base-fw context in admin RAM:
- gateway **192.168.30.1**; clients **192.168.30.10** (the workstation-RDP
  foothold), **.11**, and **.21** (dominant, ×239).
So the `192.168.30.10` RDP source that hit the workstations was a **VPN-connected
client** — external → OpenVPN(base-fw) → 192.168.30.x → RDP inward. This is the
ingress path.

## Firewall logs (in admin RAM) — DMZ FTP under external attack

base-fw kernel "Allow from any to FTP" entries (DST=172.16.10.12:21) from many
external IPs on 2018-09-06, incl.:
- **185.100.87.245** (Tor exit node) ×9
- **184.105.247.238 / .252** (TTL=244, ID=54321 = masscan signature — internet scanners)
- 107.170.210.166, 51.15.67.70, 196.52.43.101/.92, 103.96.220.46, 14.139.187.125

## What this means for patient zero

The actual ingress record lives on **base-fw** (OpenVPN log mapping 192.168.30.x →
real external IP; RADIUS/NPS VPN auth). base-fw was NOT imaged, BUT admin RAM holds
rsydow-a's session into base-fw /var/log — deeper carving of admin (and the
RADIUS/NPS auth, ias.exe ×223) is the path to the external ingress IP that was
assigned 192.168.30.10/.21.

---

## VPN client → real external IP mapping (RECOVERED from admin memory, 2026-06-04)

The VPN is **SoftEther** ("SRL Remote Access VPN", SSTP + SecureNAT DHCP), gateway
192.168.30.1. admin RAM captured rsydow-a's `root@base-fw:/opt/vpnserver/server_log#
grep 192.168.30.10/.21 vpn_2018081X.log` investigation — and the grep OUTPUT (the
session-assignment log lines) is resident, mapping each internal pool IP to its
real external source:

| Pool IP | Real external IP | Provider | Date (UTC) |
|---|---|---|---|
| **192.168.30.10** (the workstation-RDP foothold) | **45.56.154.163**, **45.56.154.8** | **Linode VPS** (attacker cloud infra) | 2018-08-05/06 |
| 192.168.30.10 | 173.76.103.142 | Verizon FiOS (residential) | 2018-08-02 |
| **192.168.30.21** (dominant VPN client, ×239 in RAM) | **166.170.51.64**, **166.170.44.25**, **166.170.47.120** | AT&T cellular | 2018-08-11/13 |

Log-line shape (SecureNAT): `vpn_20180806.log:2018-08-06 20:30:31 SSTP PPP Session
[45.56.154.8:55769]: An IP address is assigned. IP Address of Client: 192.168.30.10,
Subnet Mask 255.255.255.0, Default Gateway 192.168.30.1, Domain "shieldbase.lan"`.

### Significance
The internal foothold (192.168.30.10) that RDP'd the workstations was a **SoftEther
VPN account used from external infrastructure — including a Linode VPS
(45.56.154.163/.8)**, the classic attacker anonymization hallmark. This is the
network-level ingress origin.

### Honest limits
- These sessions are 2018-08-02→13 (the days rsydow-a grepped). The EARLIEST
  192.168.30.10 session (the workstation RDP began 2018-06-27) is NOT in these
  fragments — the full base-fw `vpn_2018*.log` set is needed for the first session.
- The VPN **username/account** tied to these sessions did not co-reside cleanly in
  the captured scrollback (SoftEther logs it on a separate connection line);
  base-fw's logs or the FreeRADIUS auth records on hunt would supply it.

---

## VPN usernames recovered (SoftEther SID-<USER> from admin memory, 2026-06-04)

SoftEther names each session `SID-<USERNAME>-[SSTP]-<n>`; admin RAM (base-fw log
scrollback) carries them, tying the account to its real external source:

| VPN account | Pool IP | Real external IP | Provider | Date |
|---|---|---|---|---|
| **MHILL** | 192.168.30.10 (foothold) | **45.56.154.163 / 45.56.154.8** | **Linode VPS** | 2018-08-05/06 |
| TDUNGAN | 192.168.30.10 (foothold) | 173.76.103.142 | Verizon FiOS | 2018-08-02 |
| RSYDOW (×12 sessions) | 192.168.30.21 | 166.170.51.64 / .44.25 / .47.120 | AT&T cellular | 2018-08-08→13 |

### Reading
- **`MHILL`'s VPN account, used from a Linode VPS to obtain the foothold IP
  192.168.30.10, is the clearest attacker-infrastructure indicator** — a
  corporate VPN credential authenticating from a cloud VPS. Maria Hill's account
  was compromised and used as the remote-access entry.
- `RSYDOW` is the IT admin (the same `rsydow-a` whose creds drove the internal
  lateral movement, and who was grepping these very logs); his 12 VPN sessions
  from AT&T cellular are consistent with legitimate remote admin BUT his account
  was also abused internally — treat as compromised.
- `TDUNGAN` from a Verizon residential IP onto the same foothold pool IP is
  ambiguous (legit remote work vs. a second compromised account).

### Source note
The usernames came from **SoftEther session IDs in admin memory**, not from
hunt's FreeRADIUS — hunt's RAM held only the FreeRADIUS *dictionary* files
(attribute defs), not resident radacct/auth records. base-fw's own
`/var/log` (SoftEther + radius) would give the complete session list incl. the
earliest (pre-August) foothold session.
