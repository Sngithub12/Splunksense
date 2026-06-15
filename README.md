# Splunksense
SplunkSense is an AI-powered incident response platform that combines Dynatrace observability data with Splunk analytics and AI-driven workflows.
AI-powered incident investigation and remediation platform.

## Features
- Incident ingestion from Dynatrace
- MCP-powered investigations
- AI root cause analysis
- Forecasting
- Remediation workflows
- Audit logging

## Architecture
![Architecture](architecture_diagram.pdf)

## Installation

git clone <repo>

cd splunksense

pip install -r requirements.txt

## Configuration

Create a .env file:

DYNATRACE_URL=
DYNATRACE_TOKEN=
SPLUNK_HOST=
SPLUNK_TOKEN=

## Running

python app.py

## Demo

Link to video

## Project Structure

app.py
templates/
static/
data/

## Dependencies

Flask
Requests
Pandas
Plotly

## Example Dataset

sample_incidents.json

## License

MIT
