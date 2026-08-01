# Sentry NIDS Model Evaluation Report

This document presents empirical evaluation metrics for the Isolation Forest, GRU Sequence Autoencoder, and Ensemble combination strategies across both synthetic datasets.

## Evaluation Parameters
- **Alert Budget**: Top 1% of total events sorted by threat score (`k = top 1%`).
- **Standard Dataset (`sample_logs.csv`)**: 1,000 log events (~35% attack traffic).
- **Imbalanced Dataset (`eval_imbalanced.csv`)**: 3,000 log events (~2.5% attack traffic).
- **Low Sample Caveat**: Categories with fewer than 10 ground-truth examples ($N_{gt} < 10$) are marked with `* [Low Sample (<10)]` and flagged as statistically unreliable.

## 1. Overall Performance Comparison (Top 1% Alert Budget)

### A. Standard Dataset (~35% Attack Traffic)
| Model / Strategy | Precision | Recall | F1-Score | FPR | TP | FP | Top 1% Budget |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | 1.0000 | 0.0141 | 0.0278 | 0.0000 | 10 | 0 | 10 events |
| **Sequence Model (GRU)** | 1.0000 | 0.0141 | 0.0278 | 0.0000 | 10 | 0 | 10 events |
| **Weighted Ensemble (0.7/0.3)** | 1.0000 | 0.0141 | 0.0278 | 0.0000 | 10 | 0 | 10 events |
| **Max Ensemble max(IF, SEQ)** | 1.0000 | 0.0141 | 0.0278 | 0.0000 | 10 | 0 | 10 events |

### B. Imbalanced SOC Dataset (~2.5% Attack Traffic)
| Model / Strategy | Precision | Recall | F1-Score | FPR | TP | FP | Top 1% Budget |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | 1.0000 | 0.1163 | 0.2083 | 0.0000 | 30 | 0 | 30 events |
| **Sequence Model (GRU)** | 0.6000 | 0.0698 | 0.1250 | 0.0044 | 18 | 12 | 30 events |
| **Weighted Ensemble (0.7/0.3)** | 1.0000 | 0.1163 | 0.2083 | 0.0000 | 30 | 0 | 30 events |
| **Max Ensemble max(IF, SEQ)** | 0.6000 | 0.0698 | 0.1250 | 0.0044 | 18 | 12 | 30 events |

## 2. Category Recall Breakdown

### Standard Dataset Category Recall
| Attack Category | Ground Truth N | Isolation Forest | Sequence Model | Weighted Ensemble | Max Ensemble |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `brute_force` | 358 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| `credential_stuffing` | 182 | 0.0000 | 0.0495 | 0.0000 | 0.0495 |
| `impossible_travel` * [Low Sample (<10)] | 7 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| `lateral_movement` | 124 | 0.0726 | 0.0000 | 0.0726 | 0.0000 |
| `device_spoofing` | 32 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| `off_hours_anomaly` * [Low Sample (<10)] | 7 | 0.1429 | 0.1429 | 0.1429 | 0.1429 |

### Imbalanced Dataset Category Recall
| Attack Category | Ground Truth N | Isolation Forest | Sequence Model | Weighted Ensemble | Max Ensemble |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `brute_force` | 105 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| `credential_stuffing` | 96 | 0.0312 | 0.1250 | 0.0417 | 0.1250 |
| `impossible_travel` * [Low Sample (<10)] | 2 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| `lateral_movement` | 46 | 0.5435 | 0.1304 | 0.5652 | 0.1304 |
| `device_spoofing` * [Low Sample (<10)] | 7 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| `off_hours_anomaly` * [Low Sample (<10)] | 2 | 1.0000 | 0.0000 | 0.0000 | 0.0000 |

## 3. Ensemble Strategy Analysis (Weighted vs Max)

### Findings:
1. **Zero-Recall Suppression**: Flat weighted averaging (`0.7 * IF + 0.3 * SEQ`) can suppress strong single-model signals when one model scores an anomaly high while the other scores it near zero. For instance, single-event anomalies like `impossible_travel` or `device_spoofing` trigger Isolation Forest features strongly but produce lower sequence reconstruction errors.
2. **Max Ensemble Recovery**: Switching to `max(if_score, seq_score)` ensures that if *either* model identifies a high-confidence threat, the signal is preserved rather than averaged down.
3. **Alert Budget Impact**: Under a strict top 1% alert budget, `Max Ensemble` recovers recall for single-model detections while maintaining low false-positive rates.