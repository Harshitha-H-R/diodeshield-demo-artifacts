# Threat model

Assets include OT/PLC/SCADA systems, the data diode, receive sensor, gateway,
alerts, evidence, models and configuration. Threats include spoofing,
reconnaissance, beaconing, protocol abuse, exfiltration, compromised gateways,
sensor disruption, model evasion and evidence tampering.

The sensor is passive and non-inline. It cannot observe management-plane traffic
or prove a physical diode failure without telemetry. Alerts are evidence for
investigation; the system does not block traffic, shut down OT, probe hosts, or
send commands through the diode.
