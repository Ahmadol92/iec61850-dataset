# IEC 61850 Cybersecurity Dataset

This repository contains supplementary materials for the paper:

"Risk-Observability Mismatch in an IEC 61850 Digital Substation: A Structured Cyber-Physical Assessment"

## Repository Contents

- IEC 61850 attack traces
- Time-series generation scripts
- Supplementary threat catalog
- Reproducibility artifacts

## Included Attack Scenarios

- TCP SYN Flood
- Volumetric DoS
- GOOSE False Data Injection (FDI)

## Reproducing Figures

Run:

python scripts/Time-series_plotting_script.py --data-dir ./data --out-dir ./figures --zip

## Dependencies

- numpy
- pandas
- matplotlib
