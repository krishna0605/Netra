# Netra Anomaly Engine

This folder is reserved for the Phase 1 AI-assisted anomaly implementation.

Phase 0 keeps runtime behavior unchanged. Phase 1 will move feature extraction,
statistical scoring, and investigator-facing explanations into the `netra_ml`
package so the Django backend can call the logic without mixing ML code into
views.
