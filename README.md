# IEC 61850 Smart Grid Attack Dataset

**A labeled network-traffic dataset for IEC 61850-based digital substation security research**


---

## Overview

This repository contains the labeled PCAP/PCAPNG dataset produced as supplementary material for the paper:

> **Risk-Observability Mismatch in an IEC 61850 Digital Substation: A Structured Cyber-Physical Assessment**  
> Yaman Alolabi and Livinus Obiora Nweke  
> Noroff University College, Norway; Norwegian University of Science and Technology (NTNU), Norway  
>

The dataset consists of **six packet captures** recorded within the [SGSim](https://doi.org/10.3390/electronics13122318) emulated smart grid environment: three baseline (normal operation) captures and three attack captures. Unlike many IEC 61850 datasets where attack scenarios are selected arbitrarily, every attack file in this repository corresponds to a threat that was first identified via the **STRIDE** framework, scored with **CVSS v3.1**, and ranked as High or Critical priority before any simulation was executed.

The dataset is intended to support:
- Anomaly-based and ML-based intrusion detection research for IEC 61850
- IDS rule development (Snort, Suricata, Zeek)
- Forensic analysis and attack-pattern recognition
- Reproducibility of the threat modelling methodology described in the paper

---

## Repository Structure

```
iec61850-dataset/
├── data/
│   ├── baseline/
│   │   ├── Baseline_104_traffic.pcap        # Normal IEC 60870-5-104 traffic
│   │   ├── Baseline_goose_traffic.pcap      # Normal GOOSE traffic
│   │   └── Baseline_sv_traffic.pcap         # Normal Sampled Values traffic
│   └── attacks/
│       ├── Built_in_DoS_attack.pcap         # Volumetric DoS (⚠ stored via Git LFS)
│       ├── Script_based_DoS_attack.pcap     # Resource-exhaustive SYN flood
│       └── Built_in_FDI_attack.pcapng       # False Data Injection on GOOSE
├── docs/
│   └── dataset_description.md              # Full technical documentation
├── .gitattributes                           # Git LFS configuration
└── README.md
```

---

## Dataset Summary

| File | Type | Duration | Frames | Avg pps | Size | Threat ID |
|------|------|----------|--------|---------|------|-----------|
| `Baseline_104_traffic.pcap` | Normal | 60.5 s | 388 | 6.4 | 50 KB | — |
| `Baseline_goose_traffic.pcap` | Normal | 32.2 s | 66 | 2.1 | 17 KB | — |
| `Baseline_sv_traffic.pcap` | Normal | 30.9 s | 1,258 | 40.7 | 191 KB | — |
| `Built_in_DoS_attack.pcap` | Attack | 17.1 s | 729,767 | 42,690 | 61.2 MB | T-I-008, T-G-008 |
| `Script_based_DoS_attack.pcap` | Attack | 41.4 s | 1,511 | 36.5 | 133 KB | T-I-008 |
| `Built_in_FDI_attack.pcapng` | Attack | 29.4 s | 6,800 | 231 | 1.66 MB | T-G-001, T-G-010 |


---

## Capture Environment

| Parameter | Value |
|-----------|-------|
| Emulation platform | SGSim ([Holík et al., 2024](https://doi.org/10.3390/electronics13122318)), Mininet 2.3.0d6 |
| Host OS | Linux kernel 6.0 (Ubuntu-based VM) |
| Capture tool | Wireshark / tshark |
| FDI capture interface | `DPSMV-eth2` (Digital Primary Substation mirror) |
| File formats | PCAP (baseline and DoS); PCAPNG (FDI) |

All experiments were conducted in a **closed, isolated virtual machine** — no real infrastructure was accessed or affected.

---

## Attack Descriptions

### 1. Baseline Captures
Three captures representing **normal IEC 61850 operation** across all protocol layers:
- **IEC 104**: Stable request–response sessions between DSS1RTU (1.1.1.1), DSS2RTU (1.1.2.1), and CONTROL (1.1.10.10) on TCP port 2404. Zero TCP errors.
- **GOOSE**: Periodic multicast frames from IED1 (`b4:b1:5a:0a:b4:01`) and IED4 (`00:30:a7:00:00:04`) to `01:0c:cd:01:00:06`. APPID `0x0001`, frame length 221 bytes, `stNum` stable at 1.
- **SV**: Continuous 40.7 pps multicast stream from IED2 and IED3, APPID `0x4000`, consistent 103-byte frames.

### 2. Volumetric Denial of Service (`Built_in_DoS_attack.pcap`)
**Method:** SGSim built-in DoS module  
**Target:** CONTROL server (1.1.10.10), TCP port 2404  
**STRIDE category:** Denial of Service  
**CVSS v3.1 base score:** 8.3 (HIGH) — Threat T-G-008

729,699 of 729,767 frames (99.99%) are flood-generated TCP frames. Packet rate reaches ~42,700 pps versus the 6.4 pps baseline. The SCADA HMI displayed an explicit DoS alert indicator on DSS1 GW within seconds of the attack start. This scenario corresponds to the **overt disruption** manifestation class discussed in the paper (Section 6.2).

### 3. Resource-Exhaustive SYN Flood (`Script_based_DoS_attack.pcap`)
**Method:** Custom Python/Scapy script  
**Target:** CONTROL server (1.1.10.10), TCP port 2404  
**STRIDE category:** Denial of Service  
**CVSS v3.1 base score:** 7.5 (HIGH) — Threat T-I-008

353 TCP SYN packets from **163 unique spoofed source IPs** (1.1.3.x subnet), with no completed three-way handshakes. Overall traffic volume remains low (36.5 pps) — **no SCADA HMI alarm was triggered**, illustrating a stealth availability attack invisible to volume-based monitoring. Also contains 896 ARP frames and 166 legitimate IEC 104 frames showing partial session continuity. This scenario corresponds to the **stealth degradation** manifestation class discussed in the paper (Section 6.3).

### 4. False Data Injection (`Built_in_FDI_attack.pcapng`)
**Method:** SGSim built-in FDI module (GOOSE publisher spoofing)  
**Target:** GOOSE subscribers on multicast `01:0c:cd:01:00:06`  
**STRIDE category:** Tampering / Spoofing  
**CVSS v3.1 base score:** 9.3 (CRITICAL) — Threats T-G-001, T-G-010

Of the 6,800 GOOSE frames, 6,742 originate from the spoofed attacker MAC `00:06:5b:00:00:66`. The injected frames are **protocol-compliant** — correct APPID (`0x0001`), authentic `gocbRef`, valid frame length — and are distinguishable from legitimate traffic only by source MAC and by the injected float value (`10.0078` vs. baseline `~5.0`). Receiving IEDs accepted the frames as legitimate, resulting in incorrect circuit breaker state representation on the SCADA HMI. This scenario corresponds to the **integrity-preserving continuity** manifestation class discussed in the paper (Section 6.4).

---

## Labeling Scheme

The dataset is labeled at **file level**. Each file represents one experimental condition.

| File | Label | Attack Class | Protocol | STRIDE Category |
|------|-------|-------------|----------|----------------|
| `Baseline_104_traffic.pcap` | Normal | — | IEC 104 | — |
| `Baseline_goose_traffic.pcap` | Normal | — | GOOSE | — |
| `Baseline_sv_traffic.pcap` | Normal | — | SV | — |
| `Built_in_DoS_attack.pcap` | Attack | Volumetric DoS | IEC 104 | Denial of Service |
| `Script_based_DoS_attack.pcap` | Attack | Resource-Exhaustive DoS | IEC 104 | Denial of Service |
| `Built_in_FDI_attack.pcapng` | Attack | False Data Injection | GOOSE | Tampering / Spoofing |

**Deriving packet-level labels** (Wireshark/tshark display filters):

```
# FDI attack frames within Built_in_FDI_attack.pcapng
eth.src == 00:06:5b:00:00:66

# SYN flood packets within Script_based_DoS_attack.pcap
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 2404
```

---
