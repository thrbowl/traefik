# Metrics Definition

## Prometheus

```toml
# Metrics definition
[metrics]
  #...

  # To enable Traefik to export internal metrics to Prometheus
  [metrics.prometheus]

    # Name of the related entry point
    #
    # Optional
    # Default: "traefik"
    #
    entryPoint = "traefik"

    # Buckets for latency metrics
    #
    # Optional
    # Default: [0.1, 0.3, 1.2, 5]
    #
    buckets = [0.1,0.3,1.2,5.0]

  # ...
```

## DataDog

```toml
# Metrics definition
[metrics]
  #...

  # DataDog metrics exporter type
  [metrics.datadog]

    # DataDog's address.
    #
    # Required
    # Default: "localhost:8125"
    #
    address = "localhost:8125"

    # DataDog push interval
    #
    # Optional
    # Default: "10s"
    #
    pushInterval = "10s"

  # ...
```

## StatsD

```toml
# Metrics definition
[metrics]
  #...

  # StatsD metrics exporter type
  [metrics.statsd]

    # StatD's address.
    #
    # Required
    # Default: "localhost:8125"
    #
    address = "localhost:8125"

    # StatD push interval
    #
    # Optional
    # Default: "10s"
    #
    pushInterval = "10s"

  # ...
```
### InfluxDB

```toml
[metrics]
  # ...

  # InfluxDB metrics exporter type
  [metrics.influxdb]

    # InfluxDB's address.
    #
    # Required
    # Default: "localhost:8089"
    #
    address = "localhost:8089"

    # InfluxDB push interval
    #
    # Optional
    # Default: "10s"
    #
    pushinterval = "10s"

  # ...
```

## Statistics

```toml
# Metrics definition
[metrics]
  # ...

  # Enable more detailed statistics.
  [metrics.statistics]

    # Number of recent errors logged.
    #
    # Default: 10
    #
    recentErrors = 10

  # ...
```
