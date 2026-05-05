# AI IDS-SIEM

AI-DRIVEN IDS is a Python-based Intrusion Detection and Security Information and Event Management project that uses machine learning to classify network traffic, assign severity levels, and help monitor suspicious activity. The project includes model loading, severity mapping, dashboard filtering, and multiple levels of testing to validate system behavior.

## Features

- Network traffic classification using a trained machine learning model.
- Severity mapping for detected attack types.
- Fallback handling when the model file is missing.
- Dashboard filtering logic for reviewing alerts.
- Unit, integration, system, and validation testing.
- Designed to support security monitoring and threat analysis.


## Requirements

- Python 3.12+
- pip
- pytest
- joblib
- pandas
- scikit-learn
- Node.js and npm for JavaScript dashboard tests

## Installation

1. Install Python dependencies:

```bash
pip install -r requirements.txt
```

If you do not have a `requirements.txt` yet, install the needed packages manually:

```bash
pip install pytest joblib pandas scikit-learn
```


## Severity Mapping

The project maps detected labels into severity levels such as:

- `INFO`
- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

Examples:
- `BENIGN` → `INFO`
- `PortScan` → `HIGH`
- `DDoS` → `CRITICAL`
- `Web Attack - XSS` → `MEDIUM`

## Running the Project

Run the application using your main entry script, for example:

```bash
python app/capture/live_capture.py
```

Adjust the command if your main script is located elsewhere.


## Test Coverage Summary

The project includes tests for:

- Severity classification logic.
- Model loading and fallback behavior.
- Integration of model artifacts and severity mapping.
- System-level behavior for normal traffic and attack scenarios.
- Validation of project goals such as attack type display, severity display, and monitoring usefulness.

## Example Test Cases

### Severity tests
- `DDoS` should map to `CRITICAL`.
- `PortScan` should map to `HIGH`.
- `Web Attack - XSS` should map to `MEDIUM`.
- `BENIGN` should map to `INFO`.


## Dashboard Filtering

The dashboard includes JavaScript filter logic to help users search and review security events more efficiently. This makes it easier to isolate suspicious records, compare attack types, and focus on higher-severity events.

## Expected Outcome

The IDS system should:
- Detect and classify traffic.
- Assign meaningful severity levels.
- Support monitoring of suspicious traffic.
- Provide useful output for administrators and analysts.
- Pass unit, integration, system, and validation testing.

## Authors

ARMANDO NELVIO MOIANE 
ADELAIDE FELICIANO LAMPIAO MIGUEL

