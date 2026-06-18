# Netra ML Anomaly Benchmark

- Model version: `netra-anomaly-20260616180955`
- Model type: `RandomForestClassifier`
- Trained rows: `6`
- Model artifact: `/app/ml-services/anomaly-engine/models/anomaly-model.pkl`
- Metadata: `/app/ml-services/anomaly-engine/models/anomaly-model.json`

## Metrics

| Metric | Value |
|---|---:|
| precision | 1.0 |
| recall | 1.0 |
| f1 | 1.0 |
| confusionMatrix | [[1, 0], [0, 5]] |

## Rows

| Case | Label | Prediction | Score |
|---|---:|---:|---:|
| bench-normal | 0 | 0 | 0.275 |
| bench-hydra-ssh | 1 | 1 | 0.9625 |
| bench-hydra-ftp | 1 | 1 | 1.0 |
| bench-distcc-rce | 1 | 1 | 1.0 |
| bench-smtp | 1 | 1 | 1.0 |
| bench-netbios | 1 | 1 | 0.9625 |

## Limitations

- This model is trained on the available local benchmark manifest and is not independent legal certification.
- Fallback explainable scoring remains active when the model artifact is unavailable.
