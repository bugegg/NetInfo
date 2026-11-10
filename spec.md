# PingInfoView for macOS — Specification

## 1. Overview

PingInfoView is a desktop ping monitor for macOS. It pings many hosts at a fixed
interval over ICMP or TCP, keeps running per-host statistics, and shows them in a
sortable grid with a per-host ping history underneath. It also discovers
device details (MAC address, hostname, vendor, open ports, a device-type guess)
for hosts that answer.

It is a clean-room reimplementation of NirSoft's Windows utility of the same
name, and follows that tool's terminology, column names, host-list syntax and
export formats where practical.

| Item | Value |
|---|---|
| Language | Python 3.14 |
| GUI toolkit | PyQt6 ≥ 6.11 (the only runtime dependency) |
| Platform | macOS 11+ (relies on `arp`, `ifconfig`, `dscacheutil`, unprivileged ICMP sockets) |
| Privileges | None — no root, no setuid (Check LLDP/CDP needs `access_bpf` group membership, see §9.3) |
| Tests | pytest, 157 tests |

## 2. Goals and non-goals

**Goals**

- Monitor hundreds of hosts at once (default up to 500 concurrent pings) without
  freezing the UI.
- Report the same statistics PingInfoView does (success/failure counts, streaks,
  RTT min/avg/max, last success/failure times).
- Need no elevated privileges.
- Make it easy to scan the local network with no setup.
- Identify devices on the LAN on a best-effort basis.

**Non-goals**

- IPv6 pinging (only IPv4 is resolved and pinged).
- OS/product fingerprinting or SYN/stealth scanning. The grid's port probe
  only checks a short list and reports hedged guesses; the Port Scan window
  (§9.3) is a plain TCP connect / UDP probe scan of one host.
- Persisting statistics or history between sessions.

## 3. Project layout

```
Pininfoview/
├── requirements.txt            PyQt6>=6.11
├── PingInfoView.app/           macOS bundle; launcher runs .venv python -m NetInfoView
├── NetInfoView/
│   ├── __main__.py             entry point, fd-limit raise, CLI host-list argument
│   ├── settings.py             Settings dataclass + QSettings persistence
│   ├── ping/                   Qt-free networking layer
│   │   ├── engine.py           asyncio scheduler (PingEngine, PingTarget, EngineOptions)
│   │   ├── icmp.py             ICMP echo over SOCK_DGRAM/IPPROTO_ICMP
│   │   ├── tcp.py              TCP connect "ping"
│   │   ├── result.py           PingStatus, PingResult, ICMP error mapping
│   │   ├── arp.py              MAC lookup from `arp -a -n`
│   │   ├── hostname.py         dscacheutil / reverse DNS, then asks the device (below)
│   │   ├── mdns.py             mDNS (unicast + multicast) and LLMNR reverse lookups
│   │   ├── netbios.py          NetBIOS node-status name (UDP 137)
│   │   ├── ntlm.py             computer name from the NTLM challenge over SMB / RDP
│   │   ├── snmp.py             SNMP sysName (community "public")
│   │   ├── ssdp.py             UPnP friendlyName via SSDP discovery
│   │   ├── tls_cert.py         host name on a device's TLS certificate
│   │   ├── http_title.py       web page <title> as a last resort
│   │   ├── ber.py              minimal ASN.1 BER/DER encode/walk
│   │   ├── port_scan.py        port probe + device-type guess
│   │   ├── port_scanner.py     Port Scan window's TCP/UDP scan of one host
│   │   ├── dhcp_probe.py       DHCP server check: DHCPINFORM as a relay agent
│   │   ├── device_info.py      batch resolver for MAC/hostname/vendor/ports/all IPs
│   │   ├── mtu.py              path MTU search via /sbin/ping -D
│   │   ├── tracepath.py        per-hop path MTU (Trace Path MTU)
│   │   ├── lldp_cdp.py         LLDP/CDP frames heard on the Mac's ports via BPF
│   │   ├── dns_ptr.py          PTR lookup against the system's DNS servers
│   │   ├── network_interfaces.py  active IPv4 interfaces from `ifconfig`
│   │   └── vendor_update.py    vendor DB fetch: GitHub copy or IEEE MA-L/MA-M/MA-S CSVs
│   ├── model/                  data model
│   │   ├── host.py             HostEntry (one grid row + statistics)
│   │   ├── columns.py          the single column table
│   │   ├── table_model.py      HostTableModel + HostFilterProxy
│   │   └── history.py          HistoryModel (ring buffer) + HistoryFilterProxy
│   ├── fileio/
│   │   ├── hostfile.py         host-list parse/format
│   │   ├── export.py           7 export formats
│   │   └── vendor_db.py        SQLite OUI database, longest-prefix lookup
│   └── ui/
│       ├── main_window.py      main window, actions, timers
│       ├── engine_thread.py    QThread hosting the asyncio engine
│       ├── device_info_thread.py, vendor_update_thread.py  background QThreads
│       ├── add_hosts_dialog.py, options_dialog.py, network_select_dialog.py
│       ├── tracepath_window.py Trace Path MTU window + its QThread
│       ├── lldp_cdp_window.py  LLDP/CDP Status window + its QThread
│       └── icons.py            status dots + gear icon drawn at runtime
└── tests/                      pytest suite (+ fixtures/ifconfig_sample.txt)
```

**Layering rule:** `ping/` and `settings.Settings` (the dataclass) don't import
Qt. `settings` imports QSettings only inside `save()`/`load()`. All Qt code lives
in `model/` and `ui/`.

## 4. Architecture

### 4.1 Threads

| Thread | Owner | Work |
|---|---|---|
| GUI thread | `MainWindow` | Models, views, dialogs, timers |
| Engine thread | `EngineThread` (QThread running `asyncio.run`) | `PingEngine` loop; all ICMP/TCP pings |
| Device-info thread | `DeviceInfoThread` (one per sweep) | `device_info.resolve_batch` with internal thread pools |
| Vendor-update thread | `VendorUpdateThread` (one per update) | Download and import the vendor database (monthly auto check, or the menu item) |

Cross-thread communication:

- Engine → GUI: the `results_ready(list)` signal, emitted in batches every
  `FLUSH_INTERVAL_SECONDS` (0.25 s), so the GUI repaints about 4×/s instead of
  once per reply.
- GUI → Engine: `stop_pinging`, `update_options` and `update_targets` are
  marshalled onto the engine's event loop with `loop.call_soon_threadsafe`.
  If the loop has already closed, the call is silently ignored.

### 4.2 Ping engine (`ping/engine.py`)

- Each round, every enabled target whose previous ping is still in flight is
  **skipped, not queued**, so a slow host can't build up a backlog.
- Concurrency is capped by an `asyncio.Semaphore(max_concurrent)`. The semaphore
  is replaced when the limit changes.
- The time to the next round is `max(0, interval − round_elapsed)`. A stop event
  interrupts the wait.
- `stop_after_pings > 0` ends the loop after that many rounds, after waiting for
  in-flight pings to finish.
- DNS: IPv4 only (`getaddrinfo(AF_INET)`), using the first result. Answers are
  cached per host name unless `resolve_every_ping` is on. A failed lookup gives
  `Bad Destination`.
- An unexpected exception while pinging one target gives `General Failure` for
  that target. It never stops the loop.
- On exit the engine waits for in-flight tasks, sends the last batch and closes
  the ICMP socket.

### 4.3 ICMP (`ping/icmp.py`)

- One shared unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP` socket for all pings.
  Replies are matched by 16-bit sequence number. The identifier is `pid & 0xFFFF`.
- macOS returns the full IP header, so the reply TTL is read from IP offset 8.
- ICMP error replies (types 3, 4, 11, 12) are matched to the original request by
  the sequence number in the quoted datagram. This separates "unreachable" from
  a timeout.
- The socket send/receive buffers are raised to 1 MiB, halving the request down
  to 32 KiB until the kernel accepts it. Without this, the default 8 KB buffer
  drops replies when hundreds of pings are in flight.
- TTL is set with `IP_TTL`. `IP_DONTFRAG` (option 28 on macOS; Python doesn't export
  it) is applied; it works on the unprivileged socket, and an echo bigger than
  the link then fails with EMSGSIZE (Packet Needs To Be Fragmented). If the kernel rejects it, the
  `dont_fragment_supported` flag is cleared and the Options dialog greys the
  option out.
- The payload is `ping_size` bytes of a repeating `a…w` pattern. The checksum
  follows RFC 1071.
- Send errors map to statuses: `ENETUNREACH/ENETDOWN` → Net Unreachable,
  `EHOSTUNREACH/EHOSTDOWN` → Host Unreachable, `ENOBUFS/EAGAIN` → No Resources,
  anything else → General Failure.

### 4.4 TCP ping (`ping/tcp.py`)

Used for hosts written as `host:port`. The RTT is the time to complete the TCP
handshake. The connection is closed straight away. No TTL is reported. Refused
or reset → `Connection Refused`. Timeout → `Request Timeout`. Other errors map
the same way as ICMP send errors.

### 4.5 Ping statuses (`ping/result.py`)

`Succeeded`, `Request Timeout`, `Destination Net Unreachable`,
`Destination Host Unreachable`, `Destination Protocol Unreachable`,
`Destination Port Unreachable`, `Packet Needs To Be Fragmented`,
`Administratively Prohibited`, `TTL Expired In Transit`, `Source Quench`,
`Bad Destination`, `No Resources`, `General Failure`, `Connection Refused`.

How ICMP error types and codes map to statuses:

| Type | Code | Status |
|---|---|---|
| 3 | 0 / 1 / 2 / 3 / 4 | Net / Host / Protocol / Port Unreachable / Fragmentation Needed |
| 3 | 9, 10, 13 | Administratively Prohibited |
| 3 | other | Host Unreachable |
| 4 | any | Source Quench |
| 11 | any | TTL Expired In Transit |
| 12 | any | Bad Destination |
| other | — | General Failure |

## 5. Data model

### 5.1 HostEntry (`model/host.py`)

Identity: `key` (unique int from a session counter), `host`, `port` (None = ICMP),
`description`, `group`, `order`, `enabled`.

Discovered: `ip_address`, `reply_ip`, `mac_address`, `hostname`, `vendor`,
`open_ports` (int for TCP, `"<port>/udp"` for UDP), `device_type_guess`,
`all_resolved_ips`, plus the `ports_scanned` / `all_ips_resolved` flags. These
flags tell "looked up, found nothing" apart from "not looked up yet".

Statistics are updated one result at a time, so memory stays flat over long runs:

- success: `succeed_count++`, reset the failure streak, set `last_succeed_on`,
  update the RTT total/min/max.
- failure: `failed_count++`, `consecutive_failed++`, set `last_failed_on`,
  update `max_consecutive_failed` and `max_consecutive_failed_seconds` (wall-clock
  length of the longest failure streak).
- derived: `total_sent`, `percent_failed`, `average_rtt_ms` (RTT total ÷ successes).

`reset_statistics()` (Clear Statistics) clears every counter and `reply_ip`, but
keeps identity and discovered device info.

### 5.2 Columns (`model/columns.py`)

`COLUMNS` is the only definition of the grid columns. The view, sorting, copy and
every export format all read it. Each `Column` has a key, title, default width, a
numeric flag (right-aligned), a value function, an optional text formatter and an
optional sort-key override.

| Key | Title | Notes |
|---|---|---|
| host_name | Host Name | `host` or `host:port`; status-dot icon; IP-aware sort |
| ip_address | IP Address | IP-aware sort; **default sort, ascending** |
| all_resolved_ips | All Resolved IPs | comma-joined |
| reply_ip | Reply IP Address | IP-aware sort |
| mac_address | MAC Address | |
| hostname | Hostname | the device's own name (DNS/mDNS, else asked of the device: SMB, NetBIOS, SNMP, UPnP, …) |
| dns_name | DNS Name | the address's PTR name from the system's DNS servers only |
| vendor | Vendor | from the OUI database, or `(Private/Randomized MAC)` |
| open_ports | Open Ports | comma-joined |
| device_type | Device Type (Guess) | |
| mtu | MTU | path MTU from Check MTU ("≥8212" at the measurable cap); "No reply" if the host didn't answer |
| succeed_count, failed_count | Succeed Count, Failed Count | |
| consecutive_failed, max_consecutive_failed | Consecutive Failed, Max. Consecutive Failed | |
| max_consecutive_failed_time | Max. Consecutive Failed Time | `H:MM:SS` |
| percent_failed | % Failed | `12.3%`, blank before any pings |
| total_sent | Total Sent Pings | |
| last_status | Last Ping Status | |
| last_rtt, average_rtt, min_rtt, max_rtt | Last/Average/Minimum/Maximum Ping Time | whole milliseconds |
| last_ttl | Last Ping TTL | |
| last_succeed_on, last_failed_on | Last Succeed On, Last Failed On | `YYYY-MM-DD HH:MM:SS` local time |
| description, group, order | Description, Group, Order | |
| disabled | Disabled | `Yes` when disabled |

**Sorting rules** (`HostFilterProxy.lessThan`):

- Columns sort by their natural-typed value, not the displayed text.
- IPv4 text sorts numerically; names and blanks come after all addresses,
  compared case-insensitively.
- Empty (`None`) values stay at the bottom in **both** ascending and descending
  order.
- Strings compare case-insensitively. Mixed types fall back to comparing as
  strings.

### 5.3 Table model behaviour

- Live results go through `dataChanged` on the changed rows only, never a model
  reset, so sort order, scroll position and selection stay put.
- Odd rows get a background tint when "Mark Odd/Even Rows" is on: `#F5F5F5`, or
  `#2D2D2D` with a black background.
- Status dot in column 0: green = last ping succeeded, red = failed,
  dark grey = Destination Host Unreachable, grey = never pinged,
  pale grey = disabled.

**Filter** (`HostFilterProxy`):

- Hide Disabled removes disabled rows.
- Display mode `succeeded` or `failed` shows only rows whose last status matches.
  Rows that have never been pinged are hidden in both modes.
- When a filtered display mode is active, the filter is re-run after every batch
  of results.

### 5.4 Ping history (lower pane, `model/history.py`)

- A `deque` ring buffer of `HistoryRecord`s (timestamp, host, IP, status, RTT,
  TTL, host key), capped at `max_accumulated_pings` (default 50,000, minimum 100).
  When the cap is reached, the oldest records are dropped.
- Columns: Ping Time, Host Name, IP Address, Status, Ping Time (ms), TTL.
- Recording modes: **every ping**, **status changes only** (the first result,
  then each success↔failure flip), or **failed pings only**.
- The pane shows history **only for the hosts selected in the grid**. With
  nothing selected, it is empty.
- Auto-scroll to the newest record is optional (on by default).

## 6. Host lists (`fileio/hostfile.py`)

Plain text, one entry per line. The same format is read by Load Host List, the
Add Hosts dialog and the command-line argument, and written by Save Host List.

```
Group: Computers Group 1      group header; applies to the lines below it
192.168.1.10 Main Server      host or IP, then an optional description
192.168.1.30:443 HTTPS Site   :port makes it a TCP ping (1–65535)
#192.168.1.14 Host 03         leading '#' adds the entry disabled
192.168.0.10-192.168.0.20     inclusive range (reversed ends are swapped)
192.168.0.10-20               short form (last octet)
192.168.0.0/24                CIDR; network/broadcast excluded unless /31 or /32
```

- Blank lines are skipped. `Group:` is matched case-insensitively.
- The Add Hosts dialog can skip the first and/or last address of every range or
  CIDR block.
- "Clear the current hosts first" (on by default, remembered) makes Add Hosts
  replace the list instead of adding to it, dropping the old hosts' history,
  graph samples and lookups as Clear All Hosts does.
- Saving writes a `Group:` header (with a blank line before it) each time the
  group changes, and puts `#` in front of disabled entries.
- An unrecognised token is kept as-is and treated as a host name.

## 7. Device discovery

### 7.1 Sweep scheduling (`MainWindow._refresh_device_info`)

- A timer fires every `DEVICE_INFO_REFRESH_MS` = 10 s.
- If the previous sweep is still running, the tick is skipped.
- Only hosts that have an IP and whose **last ping succeeded** are included.
- A host is *fully resolved*, and never looked up again, once it has a MAC,
  hostname and vendor, has been port-scanned (if scanning is on), and has had
  its all-IPs lookup done.
- Otherwise a host gets at most 6 attempts (1 + 5 retries, 10 s apart). After
  that it is left alone for the rest of the session. Clear All Hosts resets the
  attempt counts.
- Each job asks only for what is still missing (`needs_hostname`, `needs_ports`,
  `needs_all_ips`). Results only fill **empty** fields; they never overwrite.

### 7.2 Lookups (`ping/device_info.py`)

| Field | Source | Concurrency |
|---|---|---|
| MAC | `/usr/sbin/arp -a -n`, cached for 30 s, octets zero-padded and upper-cased; LAN hosts only | sequential (cached) |
| Hostname | `dscacheutil -q host -a address` (DNS + /etc/hosts + Bonjour/mDNS, 2 s timeout), falling back to `gethostbyaddr`. If neither answers and the address is private, the device itself is asked by every probe in `hostname.DEVICE_PROBES` at once, and the earliest in this order with a usable answer wins: mDNS unicast (UDP 5353), mDNS multicast (224.0.0.251), NTLM challenge over SMB (TCP 445), NTLM over RDP/NLA or else its TLS certificate (TCP 3389), NetBIOS node status (UDP 137), LLMNR (UDP 5355), SNMP `sysName` with community `public` (UDP 161), UPnP `friendlyName` via SSDP (one shared multicast M-SEARCH per 2 min, unicast fallback; description fetched only from the device's own IP), TLS certificate SAN/CN (TCP 443/8443), web page `<title>` (TCP 80/443, generic titles skipped). Each probe has a 1–2 s timeout; placeholders (`localhost…`, names with no letters or digits) are ignored; trailing dot removed | up to 24 threads (each with its own probe threads) |
| DNS Name | PTR query over UDP 53 (`ping/dns_ptr.py`, 2 s timeout) to the system's DNS servers — the main section of `scutil --dns` (`/etc/resolv.conf` as a fallback), re-read every 30 s so a VPN's DNS counts while it's up — trying each in order until one has a name; trailing dot removed | shares the hostname threads |
| Vendor | local OUI database, keyed by the first 3 octets; a locally administered MAC (bit 0x02 of the first octet set) gets `(Private/Randomized MAC)` without a database lookup | — |
| Open ports | `port_scan.scan_many` | shared pool, up to 300 threads |
| All resolved IPs | `getaddrinfo(AF_INET)` for host names only (literal IPs give `[]`), de-duplicated and sorted | up to 24 threads |

If the whole sweep raises, it returns no results, and the next tick tries again.

### 7.3 Port probe and device-type guess (`ping/port_scan.py`)

The port list comes from the Options field `port_scan_ports`, which is free text:

- Separators are commas and/or any whitespace. `#` starts a comment that runs to
  the end of the line.
- A bare number means TCP. `N/tcp` and `N/udp` are explicit.
- Invalid tokens (not a number, outside 1–65535, unknown protocol) are skipped
  without error.
- An empty field turns port scanning off.

Defaults: TCP 62078, 3389, 9100, 631, 548, 445, 139, 5900, 22, 23, 80, 443, 8080,
8443 and UDP 5353, 1900, 161, 137, 123, 67, 53. Each is written on its own line
with a `# label` comment.

- TCP: a port is open if `connect()` succeeds within 0.6 s.
- UDP: the same probe as the Port Scan window (`port_scanner.probe_udp`):
  well-known services get a request of their own kind (DNS, NTP, SNMP,
  SSDP, NetBIOS, …), anything else an empty datagram, sent twice, 0.6 s
  each. Only a reply counts as open; port unreachable and silence (open or
  firewalled, can't tell) are left out.
- Results are sorted by port number and then protocol.

The device-type guess uses TCP ports only and checks them in a fixed order. The
first match wins:

| Port | Guess |
|---|---|
| 62078 | Apple Mobile Device (iPhone/iPad) |
| 3389 | Windows (RDP) |
| 9100 | Printer (Raw/JetDirect) |
| 631 | Printer or Print Server (IPP/CUPS) |
| 548 | Mac (AFP File Sharing) |
| 445 / 139 | File Sharing (SMB — Windows or macOS) |
| 5900 | Remote Desktop/Screen Sharing (VNC) |
| 22 | SSH-enabled (Unix/Linux/macOS/Network Device) |
| 23 | Telnet-enabled (older/embedded device) |
| any of 80/443/8080/8443 | Has a Web Interface |
| none | (blank) |

Guesses describe what was seen, not a product or model. Shared protocols such as
SMB and IPP are deliberately worded with hedges.

### 7.4 MAC vendor database (`fileio/vendor_db.py`, `ping/vendor_update.py`)

- SQLite file at `~/Library/Application Support/NetInfoView/vendor.sqlite`.
  Tables: `oui(prefix TEXT PK, vendor TEXT)` and `meta(key, value)`, where
  `meta` holds `last_updated`.
- It **starts empty**; there is no bundled data. The user fills it with the
  toolbar action *Update MAC Vendor Database*, which downloads
  `https://standards-oui.ieee.org/oui/oui.csv` (30 s timeout,
  `User-Agent: PingInfoView/1.0`). The CSV must have the `Assignment` and
  `Organization Name` columns.
- The import replaces the whole table in one transaction and skips bad rows.
  A feed that is missing or empty raises `VendorUpdateError`, which is shown in
  a warning dialog.
- One connection is shared, with `check_same_thread=False`, and every access
  holds a lock, so lookups from the GUI and a background update can't collide.
- After a successful update, hosts that have a MAC but no vendor are filled in
  straight away.

## 8. Network scan on first start (`ping/network_interfaces.py`)

If Start is pressed with an empty host list:

1. List the active (`UP`), non-loopback IPv4 interfaces from `/sbin/ifconfig`,
   leaving out /31 and /32 networks. The flags word is parsed as hex, and only
   the interface's own `flags=` is read, not a bridge member's.
2. If any are found, show **Scan a Network**. It lists `en0 — 192.168.1.105
   (192.168.1.0/24)` style entries and has an *Enter Hosts Manually...* button.
3. Picking an interface expands its CIDR into one host per address and starts
   pinging. Manual entry, or finding no interfaces, opens Add Hosts instead.
   Cancel aborts.

## 9. User interface

### 9.1 Main window

- Window title "PingInfoView", 1100×620.
- A vertical splitter holds the host grid above the history pane (3:1).
- Grid: whole-row extended selection, movable and resizable columns, 20 px rows,
  no row numbers. Double-click opens the host's Ping Graph; Properties stays
  on the right-click menu (Ctrl+I).
- Ping Graph (also Show Ping Graph, Ctrl+G): a single non-modal window,
  PingPlotter style. Every host graphed while it is open (by double-click or
  Show Ping Graph, one or several at a time) gets its own panel, stacked
  below the others; all panels share one clock so they line up for comparing
  the same period. Closing the window starts the next graph afresh, and each
  panel's ✕ removes just that host (the window closes with the last one).
  The window's top row holds the span picker (1/5/10/30/60 minutes, default
  10), shared by every panel, and the span's start–end clock times.
  Panels are 250 px tall while they fit; with more hosts they shrink so all
  of them stay on one page (down to 44 px, only then scrolling), every panel
  trimmed alike so their graphs stay the same size. Below 190 px panels drop
  the jitter strip; below 110 px they hand their time labels to one shared
  strip under them all, and the ms axis shows just 0 and the top. Beyond
  three hosts the title reads "Ping Graph - N hosts".
  Each panel has:
  - a header with host (IP), Min/Avg/Max and Lost n/N (%) for the visible
    span, and ✕;
  - a jitter strip: the mean change in latency between consecutive replies
    over the last 10, as a dark-red line under a dashed scale line;
  - the latency graph: a black step line over green/amber/red bands
    (<100 ms, 100–200 ms, >200 ms), grey only before the host's first (kept) ping,
    the line carried in from the ping just before the span; each lost ping is a full-height red bar, and the right-hand PL%
    axis (0–30) carries the loss % over the last 10 pings as a red line.
  The window refreshes every second while pinging and freezes at the moment
  Stop is pressed (or stays frozen if opened while stopped), resuming on
  Start. A scroll bar along the bottom moves every panel back through the
  kept history together (right-hand end = now; a sideways swipe or
  Shift+wheel over a graph scrolls too). Scrolled back, the view stays on
  that moment while pinging carries on; back at the right-hand end it
  follows now again. Hovering shows the time and latency of the nearest ping. Samples
  are kept per host (last 3600) independently of the lower pane's recording
  mode, and dropped when the host is removed or its statistics cleared; a
  removed host's panel goes too.
- Status bar: `N item(s), Pinging|Stopped[, M Selected]`. It also shows
  temporary messages for copy, save and vendor-database updates.

### 9.2 Toolbar

Start Pinging (F5) · Stop Pinging (F6) | Add Hosts (Ctrl+N) · Clear All Hosts
(asks first) | LLDP/CDP (Ctrl+L — Check LLDP/CDP, §9.3;
icon with its label beside it) | Options (Ctrl+,) · Update MAC Vendor Database.

Start and Stop are enabled or disabled to match the engine state.

### 9.3 Context menu (right-click on the grid)

There is no menu bar; everything else is in this menu.

- Copy (⌘C — tab-delimited with a header; copies the selection, or every visible
  row if nothing is selected) · Properties (Ctrl+I — every column of the first
  selected host) · Show Ping Graph (Ctrl+G) · Check MTU — path MTU of each
  selected host: macOS rejects Don't Fragment on the app's own ICMP socket,
  so it runs `/sbin/ping -D -s <payload>`, trying 1472 bytes (1500 MTU)
  first, then a binary search; MTU = largest payload that replies + 28.
  The search goes up to the outgoing interface's MTU (`route -n get`), capped
  at 8212: an unprivileged ping can't send more than 8184 bytes of payload
  (net.inet.raw.maxdgram = 8192), so a path at the cap shows as "≥8212".
  On a 1500 interface that's one probe; on a jumbo one, 1473 bytes is tried
  next so a 1500 path is still settled in two.
  A failed size is retried once so a stray loss isn't read as "too big";
  up to 32 hosts at a time, results land in the MTU column as they come.
  It also runs by itself on the device-info timer (every 10 s): each enabled
  host is checked once, after its first successful ping; the menu item
  re-checks on demand
- Trace Path MTU (also the sidebar's Trace Path MTU button) — like Linux
  `tracepath`: opens a window listing every hop to the first selected host,
  or with nothing selected an empty one with a Target field to type an
  address or name into (Trace / Return starts it) (Hop · Address · Name · Path MTU · Note), to show
  where the MTU drops. Per hop it runs `/sbin/ping -D -m <ttl> -s <payload>`
  at the path MTU so far, starting from the outgoing interface's MTU (capped
  at 8212, as Check MTU); "Time to live exceeded" means
  that size reaches the hop. A router that answers "frag needed and DF set
  (MTU n)" has its MTU taken as is and is named in the Note; if big probes
  vanish silently while a 0-byte one still answers, a binary search finds the
  size. Silent hops show `*`. It stops when the host answers, a router reports
  it unreachable, after 30 hops, or on Stop; the row where the MTU drops is
  tinted. Names come from the same lookup as the Hostname column
- Check LLDP/CDP (Ctrl+L, also the LLDP/CDP toolbar button) — which switch,
  port and VLAN this Mac is plugged into. Opens the **LLDP/CDP Status**
  window (pressing it again while open refreshes its interface list); the
  host selection plays no part. Pick an interface from the Interface list —
  the `enN` interfaces with `status: active`, labelled with their
  `networksetup` port names; ones without a link are hidden. Wired ports
  come first, then Wi-Fi, then the rest. Refresh rescans, and Check
  re-reads the list first (keeping the choice if it's still up) — and
  press Check. It listens on that interface for 65 s — switches
  announce LLDP every 30 s and CDP every 60 s by default — through
  `/dev/bpf*` (BIOCSETIF, BIOCPROMISC, BIOCIMMEDIATE, BIOCSSEESENT off) with
  a kernel filter passing only EtherType 0x88cc and frames to
  01:00:0c:cc:cc:cc. Each switch port is reported once, as soon as it's
  heard. Status panel: LLDP and CDP each as
  Listening... / Received — switch and port / Nothing heard in n s. Below
  it, a read-only monospace text box (no table) with one block per
  announcement: "LLDP on en10 (USB 10/100/1000 LAN)" then aligned lines —
  Switch · Switch Port · Port ID · Port Description · VLAN · IP Address ·
  Management (every advertised address: IPv4, IPv6 or MAC) · Platform ·
  Capabilities · Chassis ID — then everything else it sent, in order, and
  the rest of the system description last; empty ones left out. An LLDP
  port ID that is a MAC (HPE Comware sends one) shows the port description
  as Switch Port and the MAC as Port ID. Many switches (HPE OfficeConnect
  1950, for one) advertise only a MAC as their management address; then the
  IP is looked up in the ARP table by the switch's MACs (chassis, port,
  management) and shown "(from ARP)", or "not advertised, and not found in
  the ARP table" — the switch may have no IP on the Mac's VLAN at all.
  Decoded: LLDP chassis/port ID (MAC, IPv4 or text), TTL, port
  description, system name/description, capabilities enabled and
  supported, management addresses; IEEE 802.1 port VLAN ID, protocol VLAN,
  VLAN name, link aggregation; IEEE 802.3 MAC/PHY (speed/duplex from the
  MAU type, auto-negotiation), PoE (Power via MDI), link aggregation, max
  frame size; LLDP-MED device type, network policy (voice VLAN etc.), PoE
  power, inventory (hardware/firmware/software revision, serial number,
  manufacturer, model, asset ID); any other TLV as hex. CDP: device ID,
  addresses, port, capabilities, version, platform, native VLAN. Check / Stop / Check Again and a progress bar;
  the list is locked while listening.
  BPF needs no root when the user is in the `access_bpf` group (Wireshark's
  ChmodBPF); otherwise the status line says capture isn't permitted.
- Repeat Ping… (Ctrl+Shift+P, also the sidebar's Repeat Ping button) — Cisco IOS-style `ping … repeat` to one host
  (`ping/repeat_ping.py`, `ui/repeat_ping_window.py`), the first selected
  host filled in; it starts when Ping is pressed. Each echo goes the moment
  the last is answered or times out, no interval, so the rate is set by the
  round trip (hundreds to ~1000 a second on a LAN). The window has only
  Target and Repeat count (1–2147483647, default 1000); everything else is
  Cisco's default: 100-byte datagrams (IP + ICMP headers included), 2 s
  timeout, data pattern 0xABCD, no DF. (`ping/repeat_ping.py` also takes
  size, timeout 0, DF, pattern and a size sweep, unused by the window.)
  macOS: its own blocking unprivileged ICMP socket with
  a random identifier (never the grid's), IP_DONTFRAG (28) for DF, an echo
  bigger than the link with DF fails with EMSGSIZE = M; Windows:
  IcmpSendEcho with the pattern as data. Output as IOS: "Sending n, s-byte
  ICMP Echos to ip, timeout is t seconds:" (DF and pattern lines only when
  not default), one
  character per echo, wrapped to fill the box and re-wrapped when it is
  resized (`!` reply, `.` timeout, `U`
  unreachable, `M` could not fragment, `Q` source quench, `&` TTL expired,
  `?` other; M only with DF), then "Success rate is p percent (r/s), round-trip
  min/avg/max = …" (p rounded down) and, for a DF sweep that hit M, the
  largest size that got through. A live line above shows sent / received /
  loss % / min/avg/max / echoes per second; Ping becomes Stop; Copy copies
  the text.
- Port Scan… (Ctrl+P, also the sidebar's Port Scan button) — which TCP and
  UDP ports one host has open (`ping/port_scanner.py`,
  `ui/port_scan_window.py`). Opens with the first selected host and scans
  its common TCP ports straight away, or empty for a host to be typed (an
  IP or a name; IPv4 preferred). Protocol: TCP · UDP · TCP + UDP. Ports:
  Common ports (~110 TCP: services and network gear such as Winbox,
  NETCONF, Smart Install, TR-069; ~35 UDP) · Well-known (1–1024) · All
  ports (1–65535) · Custom (`22, 80, 8000-8100`; a bad piece is named and
  nothing runs). No other settings: 1 s timeout per probe, 256 probes in
  flight, services always identified and silent UDP ports always rechecked.
  TCP: a plain `connect()` — open = handshake done, closed = refused,
  filtered = timeout or unreachable. Each
  open TCP port gets 1 s to send its own greeting (SSH, FTP, SMTP, Telnet,
  …; read on past Telnet negotiation) and its first line is shown; one
  that sends none is asked `HEAD /` as a web server (status and `Server:`
  header), and over TLS (version, certificate CN, then `HEAD /` again)
  when it answers like a TLS port or is a usual TLS port (443, 8443, 993…).
  UDP: well-known services get a request they answer, decoded where it
  helps — DHCP (`ping/dhcp_probe.py`): a server never answers the port a
  request came from, so a DHCPINFORM is sent as a relay agent forwards one
  (giaddr = this computer's address toward the target, one hop) and the
  DHCPACK is heard on UDP 67, bound without root and shared by every probe
  of a sweep (a reader thread hands replies over by transaction ID; closed
  when none waits); INFORM makes the server neither offer nor lease an
  address. Shown as "DHCP ACK · server a.b.c.d"; no reply falls back to
  the plain probe; DNS/mDNS/LLMNR PTR query (rcode, name), NTP (version, stratum),
  NetBIOS node status (name), SNMP v2c GET of sysName (the Settings
  community, then `public`), SSDP M-SEARCH and SIP OPTIONS (Server
  header), NAT-PMP (external IP), TFTP read, RPC NULL (portmapper, NFS),
  IKEv1 Main Mode, OpenVPN hard reset, RIP, IPMI presence ping, SQL
  Browser, STUN, WS-Discovery, CoAP, BACnet Who-Is, Ubiquiti discovery,
  memcached; any other port an empty datagram. Each is sent twice within
  the timeout. A reply = open (its description, first text line, or
  "replied (n bytes)"), ICMP port unreachable = closed
  (ConnectionRefusedError, or ConnectionResetError on Windows), silence =
  open|filtered. Hosts rate-limit port unreachable (Linux: a burst of six,
  then about one a second), so the silent ports are asked again, once each per round, all at once,
  round after round while a round settles any of them (at most 600
  rounds); the status line shows the round and the progress bar goes
  busy. A host without a limit costs one extra round (one timeout); a
  Linux router's ~30 common UDP ports take ~25 s and end up almost all
  closed instead of open|filtered.
  The table lists open ports, sorted by port then protocol, as they're
  found: Port (`22/tcp`) · State · Service (built-in list, else the OS
  services database) · Banner / Reply · Time; UDP ports that never replied are only counted.
  Scan sits at the right end of
  the Ports row and becomes Stop; a progress bar with the open count fills
  the gap before it while scanning. The status line sums up open / closed / filtered /
  open|filtered and time taken.
- Add Hosts · Remove Selected (Delete)
- Enable Selected · Disable Selected · Clear Statistics (selection, or all hosts)
- Load Host List (⌘O — replaces the list and clears history) · Save Host List
  (⌘S) · Save Results (⌘⇧S)
- Show All Hosts / Show Only Succeeded / Show Only Failed (pick one)
- Hide Disabled Items · Mark Odd/Even Rows · Black Background · Always On Top
- Auto Size Columns (Ctrl+Plus) · Choose Font
- Lower Pane ▸ Show Lower Pane · Auto Scroll Lower Pane · Record Every Ping /
  Status Changes Only / Failed Pings Only · Clear Lower Pane
- About (shows the vendor database's entry count and last update date)

`action_select_all` (⌘A) and `action_quit` (⌘Q) are defined but never added to
any widget, so their own shortcuts never fire. ⌘A still works through
QTableView's built-in handling, and ⌘Q through the default macOS app menu.

### 9.4 Options dialog

| Group | Field | Range / default |
|---|---|---|
| Ping | Ping every | 0.1–86400 s, default 1.0 |
| | Ping timeout | 1–600000 ms, default 3000 |
| | Ping size | 0–65500 bytes, default 32 |
| | Time to live (TTL) | 1–255, default 64 |
| | Don't fragment | off; disabled if unsupported |
| | Stop after | 0 = Unlimited … 1,000,000 rounds |
| Advanced | Maximum concurrent pings | 1–10000, default 500 |
| | Resolve host name to IP on every ping | off |
| | Start pinging immediately on startup | on |
| | Probe ports | free text, see §7.3 |
| | Keep at most (lower pane) | 100–10,000,000, default 50,000 |

Clicking OK clamps the values (`Settings.sanitised`), resizes the history buffer
and sends the new options to a running engine without restarting it.

## 10. Export (`fileio/export.py`)

*Save Results* writes the selected rows, or every visible row if nothing is
selected, with all columns, as UTF-8:

| Format | Ext | Shape |
|---|---|---|
| Text file | .txt | `Title : value` blocks separated by `=` × 70 |
| Tab delimited | .txt | header + rows, CRLF; tabs inside cells become spaces |
| CSV | .csv | `csv` module quoting, CRLF |
| Tabular | .txt | fixed-width columns sized to the widest cell |
| HTML (Horizontal) | .html | one table, a row per host |
| HTML (Vertical) | .html | a 2-column table per host |
| XML | .xml | `<ping_items><item><column_key>…` |

HTML and XML values are escaped. HTML output ends with a line
`Created by PingInfoView on <timestamp>`.

## 11. Settings persistence (`settings.py`)

- `QSettings("NetInfoView", "NetInfoView")` (a macOS plist); settings from the old `QSettings("pinginfoview", "PingInfoView")` are copied over once on first launch.
- Loaded at startup. Values that fail type conversion fall back to their
  defaults, and the result is clamped by `sanitised()`.
- Saved **only when the window closes**.
- Persisted fields: all Options-dialog values, display mode, hide disabled,
  odd/even rows, black background, always on top, font family and size, history
  mode, auto-scroll, show lower pane.

## 12. Startup and shutdown

**Startup** (`python -m NetInfoView [hostlist.txt]`):

1. Raise the soft `RLIMIT_NOFILE` to 4096 (or the hard limit, if that is lower).
   Apps launched by launchd start with a limit of 256, which is too low for the
   port-scan pool. If raising it fails, startup continues.
2. Create the QApplication, load Settings, build the MainWindow.
3. The first command-line argument that doesn't start with `-` and can be read
   is loaded as a host list.
4. If `start_ping_immediately` is on and there are hosts, start pinging.

**App bundle:** `PingInfoView.app` (bundle ID `net.local.NetInfoView`, version
1.0, minimum macOS 11). Its launcher `cd`s into a **hard-coded** project path,
runs `.venv/bin/python -m NetInfoView`, and appends stdout and stderr to
`~/Library/Logs/PingInfoView.log`.

**Shutdown:** stop the engine and wait up to 3 s. Wait up to 3 s for any
vendor-update or device-info thread. Close the vendor database. Save settings.

## 13. Performance requirements

- The GUI thread never does blocking network or subprocess I/O. Pinging, device
  lookups and vendor downloads all run on worker threads.
- Results reach the GUI at most 4 times a second, as batches.
- Memory per host stays constant over time. History memory is limited by
  `max_accumulated_pings`.
- The ICMP socket buffers are big enough for a full round of 500 concurrent
  replies.
- A 50-host port sweep with the default 21 ports takes about 2 s (measured with
  300 workers).

## 14. Testing

Run with `.venv/bin/python -m pytest`. The 157 tests cover columns, device info,
the entry point, export, history, host files, hostname resolution, MAC helpers,
the main window, network interfaces, the port scan, the vendor database and the
vendor update. `tests/fixtures/ifconfig_sample.txt` provides realistic
`ifconfig` output, including a bridge interface with hex flags.

## 15. Known limitations and observations

- **IPv4 only.** Hostnames resolve to the first A record; IPv6 literals are not
  pinged.
- **MAC/vendor are only available on the local link**, because they come from
  the ARP table.
- **Port Scan on Windows can't tell a closed TCP port from a filtered one.**
  Windows retries a connect the port refused for about 2 s, past the 1 s
  timeout, so closed ports are counted as filtered there (open ones are
  unaffected), and the "nothing answered" hint isn't shown.
- **UDP needs a reply.** A UDP service that ignores its probe isn't listed
  as open. DHCP (67) is asked as a relay agent (below), which needs UDP 67
  free on this computer; if something else holds it (Internet Sharing's
  bootpd), 67 gets the plain probe and a DHCP server shows as not open.
- **Statistics and history are not saved.** Settings are saved only when the
  window closes normally, so a crash loses any changes made to them.
- **The app bundle isn't portable.** The launcher hard-codes
  `/Users/surachaib./Documents/Pininfoview` and depends on the project's `.venv`.
- `EngineOptions.interval_seconds` defaults to 3.0 while `Settings` defaults to
  1.0. This has no effect in practice, because the engine is always given
  `EngineOptions.from_settings`.
- There are stale `__pycache__` files for modules that no longer exist
  (`vendor_logo`, `test_table_model`, `test_vendor_logo`). They can be deleted.
- `HostTableModel` and `HostFilterProxy` have no test file of their own
  (`test_table_model.py` is missing). Sorting and filtering are only tested
  indirectly, through `test_main_window.py`.
- `ui/icons.gear_icon` is defined but never used. The Options button uses a
  standard Qt icon instead.
- `action_select_all` and `action_quit` aren't attached to any widget (§9.3).
- The project isn't a git repository.
