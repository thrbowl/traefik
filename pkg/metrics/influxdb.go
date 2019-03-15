package metrics

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/containous/traefik/pkg/log"
	"github.com/containous/traefik/pkg/safe"
	"github.com/containous/traefik/pkg/types"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics/influx"
	influxdb "github.com/influxdata/influxdb/client/v2"
)

var influxDBClient *influx.Influx

type influxDBWriter struct {
	buf    bytes.Buffer
	config *types.InfluxDB
}

var influxDBTicker *time.Ticker

const (
	influxDBMetricsBackendReqsName      = "traefik.backend.requests.total"
	influxDBMetricsBackendLatencyName   = "traefik.backend.request.duration"
	influxDBRetriesTotalName            = "traefik.backend.retries.total"
	influxDBConfigReloadsName           = "traefik.config.reload.total"
	influxDBConfigReloadsFailureName    = influxDBConfigReloadsName + ".failure"
	influxDBLastConfigReloadSuccessName = "traefik.config.reload.lastSuccessTimestamp"
	influxDBLastConfigReloadFailureName = "traefik.config.reload.lastFailureTimestamp"
	influxDBEntrypointReqsName          = "traefik.entrypoint.requests.total"
	influxDBEntrypointReqDurationName   = "traefik.entrypoint.request.duration"
	influxDBEntrypointOpenConnsName     = "traefik.entrypoint.connections.open"
	influxDBOpenConnsName               = "traefik.backend.connections.open"
	influxDBServerUpName                = "traefik.backend.server.up"
)

const (
	protocolHTTP = "http"
	protocolUDP  = "udp"
)

// RegisterInfluxDB registers the metrics pusher if this didn't happen yet and creates a InfluxDB Registry instance.
func RegisterInfluxDB(ctx context.Context, config *types.InfluxDB) Registry {
	if influxDBClient == nil {
		influxDBClient = initInfluxDBClient(ctx, config)
	}
	if influxDBTicker == nil {
		influxDBTicker = initInfluxDBTicker(ctx, config)
	}

	return &standardRegistry{
		enabled:                        true,
		configReloadsCounter:           influxDBClient.NewCounter(influxDBConfigReloadsName),
		configReloadsFailureCounter:    influxDBClient.NewCounter(influxDBConfigReloadsFailureName),
		lastConfigReloadSuccessGauge:   influxDBClient.NewGauge(influxDBLastConfigReloadSuccessName),
		lastConfigReloadFailureGauge:   influxDBClient.NewGauge(influxDBLastConfigReloadFailureName),
		entrypointReqsCounter:          influxDBClient.NewCounter(influxDBEntrypointReqsName),
		entrypointReqDurationHistogram: influxDBClient.NewHistogram(influxDBEntrypointReqDurationName),
		entrypointOpenConnsGauge:       influxDBClient.NewGauge(influxDBEntrypointOpenConnsName),
		backendReqsCounter:             influxDBClient.NewCounter(influxDBMetricsBackendReqsName),
		backendReqDurationHistogram:    influxDBClient.NewHistogram(influxDBMetricsBackendLatencyName),
		backendRetriesCounter:          influxDBClient.NewCounter(influxDBRetriesTotalName),
		backendOpenConnsGauge:          influxDBClient.NewGauge(influxDBOpenConnsName),
		backendServerUpGauge:           influxDBClient.NewGauge(influxDBServerUpName),
	}
}

// initInfluxDBTicker creates a influxDBClient
func initInfluxDBClient(ctx context.Context, config *types.InfluxDB) *influx.Influx {
	logger := log.FromContext(ctx)

	// TODO deprecated: move this switch into configuration.SetEffectiveConfiguration when web provider will be removed.
	switch config.Protocol {
	case protocolUDP:
		if len(config.Database) > 0 || len(config.RetentionPolicy) > 0 {
			logger.Warn("Database and RetentionPolicy options have no effect with UDP.")
			config.Database = ""
			config.RetentionPolicy = ""
		}
	case protocolHTTP:
		if u, err := url.Parse(config.Address); err == nil {
			if u.Scheme != "http" && u.Scheme != "https" {
				logger.Warnf("InfluxDB address %s should specify a scheme (http or https): falling back on HTTP.", config.Address)
				config.Address = "http://" + config.Address
			}
		} else {
			logger.Errorf("Unable to parse the InfluxDB address %v: falling back on UDP.", err)
			config.Protocol = protocolUDP
			config.Database = ""
			config.RetentionPolicy = ""
		}
	default:
		logger.Warnf("Unsupported protocol %s: falling back on UDP.", config.Protocol)
		config.Protocol = protocolUDP
		config.Database = ""
		config.RetentionPolicy = ""
	}

	return influx.New(
		map[string]string{},
		influxdb.BatchPointsConfig{
			Database:        config.Database,
			RetentionPolicy: config.RetentionPolicy,
		},
		kitlog.LoggerFunc(func(keyvals ...interface{}) error {
			log.WithoutContext().WithField(log.MetricsProviderName, "influxdb").Info(keyvals)
			return nil
		}))
}

// initInfluxDBTicker initializes metrics pusher
func initInfluxDBTicker(ctx context.Context, config *types.InfluxDB) *time.Ticker {
	pushInterval, err := time.ParseDuration(config.PushInterval)
	if err != nil {
		log.FromContext(ctx).Warnf("Unable to parse %s from config.PushInterval: using 10s as the default value", config.PushInterval)
		pushInterval = 10 * time.Second
	}

	report := time.NewTicker(pushInterval)

	safe.Go(func() {
		var buf bytes.Buffer
		influxDBClient.WriteLoop(report.C, &influxDBWriter{buf: buf, config: config})
	})

	return report
}

// StopInfluxDB stops internal influxDBTicker which controls the pushing of metrics to InfluxDB Agent and resets it to `nil`
func StopInfluxDB() {
	if influxDBTicker != nil {
		influxDBTicker.Stop()
	}
	influxDBTicker = nil
}

// Write creates a http or udp client and attempts to write BatchPoints.
// If a "database not found" error is encountered, a CREATE DATABASE
// query is attempted when using protocol http.
func (w *influxDBWriter) Write(bp influxdb.BatchPoints) error {
	c, err := w.initWriteClient()
	if err != nil {
		return err
	}

	defer c.Close()

	if writeErr := c.Write(bp); writeErr != nil {
		ctx := log.With(context.Background(), log.Str(log.MetricsProviderName, "influxdb"))
		log.FromContext(ctx).Errorf("Error while writing to InfluxDB: %s", writeErr.Error())

		if handleErr := w.handleWriteError(ctx, c, writeErr); handleErr != nil {
			return handleErr
		}
		// Retry write after successful handling of writeErr
		return c.Write(bp)
	}
	return nil
}

func (w *influxDBWriter) initWriteClient() (influxdb.Client, error) {
	if w.config.Protocol == "http" {
		return influxdb.NewHTTPClient(influxdb.HTTPConfig{
			Addr:     w.config.Address,
			Username: w.config.Username,
			Password: w.config.Password,
		})
	}

	return influxdb.NewUDPClient(influxdb.UDPConfig{
		Addr: w.config.Address,
	})
}

func (w *influxDBWriter) handleWriteError(ctx context.Context, c influxdb.Client, writeErr error) error {
	if w.config.Protocol != protocolHTTP {
		return writeErr
	}

	match, matchErr := regexp.MatchString("database not found", writeErr.Error())

	if matchErr != nil || !match {
		return writeErr
	}

	qStr := fmt.Sprintf("CREATE DATABASE \"%s\"", w.config.Database)
	if w.config.RetentionPolicy != "" {
		qStr = fmt.Sprintf("%s WITH NAME \"%s\"", qStr, w.config.RetentionPolicy)
	}

	logger := log.FromContext(ctx)

	logger.Debugf("InfluxDB database not found: attempting to create one with %s", qStr)

	q := influxdb.NewQuery(qStr, "", "")
	response, queryErr := c.Query(q)
	if queryErr == nil && response.Error() != nil {
		queryErr = response.Error()
	}
	if queryErr != nil {
		logger.Errorf("Error while creating the InfluxDB database %s", queryErr)
		return queryErr
	}

	logger.Debugf("Successfully created the InfluxDB database %s", w.config.Database)
	return nil
}
