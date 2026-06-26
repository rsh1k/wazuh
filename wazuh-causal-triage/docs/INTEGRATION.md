# Integrating Causal Triage feedback into Wazuh

This guide wires the module's prioritized output back into Wazuh so incidents
appear as enriched, first-class alerts in the dashboard. The flow is additive
and non-destructive: the module writes a feedback file, and Wazuh ingests it via
a standard logcollector + custom decoder + custom rules. Nothing in the original
alert pipeline is modified.

## 1. Point the module at a feedback file

In your config:

```yaml
output:
  wazuh_feedback_path: /var/ossec/logs/causal_triage_feedback.json
```

Each prioritized incident is appended as one JSON object per line (NDJSON), e.g.:

```json
{"integration":"causal-triage","incident_id":"inc-WIN-HOST-...","host":"WIN-HOST","score":100.0,"priority":"critical","tactics":["Credential Access","Execution","Discovery","Lateral Movement"],"techniques":["T1110","T1059.001","T1046","T1021"],"alert_count":5,"first_seen":"...","last_seen":"...","narrative":"..."}
```

## 2. Tell Wazuh to read the file

Add a localfile block to `/var/ossec/etc/ossec.conf` on the Wazuh server (or in a
centralized agent config):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/causal_triage_feedback.json</location>
</localfile>
```

Because `log_format` is `json`, Wazuh parses each line into `data.*` fields
automatically; the custom decoder below mainly labels the source.

## 3. Add a custom decoder

Create `/var/ossec/etc/decoders/local_causal_triage_decoder.xml`:

```xml
<decoder name="causal-triage">
  <prematch>"integration":"causal-triage"</prematch>
</decoder>
```

## 4. Add custom rules

Create `/var/ossec/etc/rules/local_causal_triage_rules.xml`. Rule IDs in the
100000+ range are reserved for local custom rules.

```xml
<group name="causal_triage,">

  <rule id="100700" level="3">
    <decoded_as>causal-triage</decoded_as>
    <field name="integration">causal-triage</field>
    <description>Causal Triage: prioritized incident on $(host)</description>
  </rule>

  <rule id="100701" level="10">
    <if_sid>100700</if_sid>
    <field name="priority">high</field>
    <description>Causal Triage: HIGH priority incident on $(host) (score $(score))</description>
  </rule>

  <rule id="100702" level="13">
    <if_sid>100700</if_sid>
    <field name="priority">critical</field>
    <description>Causal Triage: CRITICAL incident on $(host) (score $(score))</description>
  </rule>

</group>
```

## 5. Restart and verify

```bash
sudo systemctl restart wazuh-manager
# Validate decoder/rule parsing against a sample line:
echo '{"integration":"causal-triage","host":"WIN-HOST","priority":"critical","score":100.0}' \
  | /var/ossec/bin/wazuh-logtest
```

`wazuh-logtest` should show the line decoding as `causal-triage` and matching
rule `100702` at level 13. Prioritized incidents will now surface in the Wazuh
dashboard like any other alert, with the full narrative available in the event
data.

## Scheduling the module

Run it on a timer. Example cron entry (every 5 minutes):

```cron
*/5 * * * * /usr/bin/wazuh-causal-triage run --config /var/ossec/integrations/causal_triage.yaml --no-stdout >> /var/log/causal_triage.log 2>&1
```

Or a systemd timer if you prefer journald integration. Keep the look-back window
comfortably larger than the run interval so no alerts fall between runs.

## A note on the adaptive baseline

The first several runs establish the score baseline; during this warm-up only
the `absolute_floor` applies. Persist the baseline (`scoring.baseline_state_path`)
so adaptation survives restarts. If you change rule levels significantly or
onboard a very different host population, consider resetting the baseline by
deleting that state file — the module will start a fresh baseline safely.
