# Netra Anomaly Engine

This package contains worker-only feature extraction, deterministic anomaly
signals, and investigator-facing explanations. The Django API does not import
this package; analysis workers load it through the isolated processing path.

Executable pickle and joblib models are not supported. Any future learned model
must use the reviewed portable-model, provenance, evaluation, and approval
contract documented by the main repository.
