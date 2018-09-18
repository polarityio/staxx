# Polarity STAXX Integration

![image](https://img.shields.io/badge/status-beta-green.svg)

Polarity's STAXX integration gives users access to automated MD5, SHA1, SHA256, IPv4, IPv6 and Domain lookups within Anomali's STAXX platform..

Anomali STAXX gives you a free, easy way to subscribe to any STIX / TAXII feed. Simply download the STAXX client, configure your data sources, and STAXX will handle the rest.

To learn more about Anomali STAXX please see their official website at [https://www.anomali.com/platform/staxx](https://www.anomali.com/platform/staxx)

> Note: This integration is currently in BETA.  Please see the [issues](https://github.com/polarityio/staxx/issues) page for known issues.

| ![image](https://user-images.githubusercontent.com/306319/45713411-fa911e80-bb5c-11e8-848f-f7d6427702ad.png)  |
|---|
|*Anomali STAXX Examples* |

## STAXX Integration Options

### Anomali STAXX Server URL

The URL for your STAXX server which should include the schema (i.e., http, https) and port if required.  For example `https://192.168.1.29:8080`

### Username

Your Anomali STAXX username

### Password

The password for the provided STAXX user

### Minimum Severity Level

A string value which specifies the minimum severity level required for an indicator to be displayed.   For example, if you set the value to high then only indicators with a severity level of "high" or "very-high" will be displayed in the notification overlay.

Allowed values are "low", "medium", "high", "very-high"

### Minimum Confidence Level

An integer value between 0 and 100 which specifies the minimum confidence level required for an indicator to be displayed.   For example, if you set the value to 55 then only indicators with a confidence of 55 or above will be displayed in the notification overlay.

### Ignore Private IPs

If set to true, private IPs (RFC 1918 addresses) will not be looked up (includes 127.0.0.1, 0.0.0.0, and 255.255.255.255)

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
