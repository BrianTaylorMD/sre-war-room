/*
 * stacks.js — WR.stacks (sourced comparison data) and WR.stackFit(traits, scale) for SPEC §6.5/§6.6b.
 *
 * Four setups: Datadog; Grafana (self-hosted LGTM or Grafana Cloud); OpenTelemetry plus a backend of
 * your choice; hosted cloud Prometheus (Azure Monitor, Amazon, Google).
 *
 * Rules this file keeps (tests/data.test.mjs checks them):
 * - A price or limit is a number only when research/verified.json has it with its source. Anything
 *   else is usd:null and the UI shows "See pricing page".
 * - Every row cites sourceIds or sets reasoning:true (often both, when a sourced fact is combined
 *   with our own inference). Every flag does the same.
 * - All text is our own wording; nothing is copied from a source.
 *
 * stackFit(traits, scale) reacts to the incident (traits from WR.traits) and to the scale inputs:
 *   multiCluster / clusterCount, highCardinalityLabels (alert label keys), errorTracesMissing,
 *   logLinesPerMin (a rate in the PASTE, not production; used only as context), untracedFailingComponents,
 *   and scale {nodes, logsGbPerDay, activeSeries, apmHosts}.
 * Levels: 'breaks' = this incident's evidence is lost or blocked by design or by a limit you are
 *   already at; 'strain' = works, but costs more, needs config, or loses detail; 'ok' = fits.
 * Verdict: any 'breaks' -> 'Strained'; two or more 'strain' -> 'Workable'; otherwise 'Good fit'.
 * Cost lines are rough list-price estimates for a 30-day month, before discounts. A cost line is a
 * number only when every input is either a verified unit price or a scale input; assumptions are
 * stated in its basis. Each cost line carries priceId (the WR.stacks price it uses) for traceability.
 */
(function (WR) {
  'use strict';

  var AS_OF = '2026-10-06';
  var DAYS = 30;
  var MINUTES_PER_MONTH = DAYS * 24 * 60; // 43,200: one sample per series per minute = a 60-second interval
  var DEFAULT_SCALE = { nodes: 40, logsGbPerDay: 50, activeSeries: 500000, apmHosts: 20 };

  // ------------------------------------------------------------------------------------------
  // Sources (every url is in research/verified.json; asOf = the day the page was checked)
  // ------------------------------------------------------------------------------------------
  function s(url, title, extra) {
    var o = { url: url, title: title, asOf: AS_OF };
    if (extra) Object.keys(extra).forEach(function (k) { o[k] = extra[k]; });
    return o;
  }
  var sources = {
    'dd-pricing': s('https://www.datadoghq.com/pricing/', 'Datadog pricing'),
    'dd-custom-metrics': s('https://docs.datadoghq.com/account_management/billing/custom_metrics/', 'Datadog docs: custom metrics billing', { updated: '2026-08-06' }),
    'dd-log-indexes': s('https://docs.datadoghq.com/logs/log_configuration/indexes/', 'Datadog docs: log indexes and daily quotas', { updated: '2026-09-11' }),
    'dd-trace-ingestion': s('https://docs.datadoghq.com/tracing/trace_pipeline/ingestion_mechanisms/', 'Datadog docs: trace ingestion mechanisms', { updated: '2026-08-19' }),
    'dd-trace-retention': s('https://docs.datadoghq.com/tracing/trace_pipeline/trace_retention/', 'Datadog docs: trace retention', { updated: '2026-09-01' }),
    'dd-otel-k8s-explorer': s('https://www.datadoghq.com/blog/native-otel-kubernetes-explorer/', 'Datadog blog: native OpenTelemetry support in Kubernetes Explorer', { published: '2026-03-23' }),
    'dd-otel-news': s('https://opensource.datadoghq.com/otel-news/2026/03/', 'Datadog open source: OTel News, March 2026 edition', { published: '2026-03' }),
    'grafana-pricing': s('https://grafana.com/pricing/', 'Grafana Cloud pricing'),
    'grafana-logs-invoice': s('https://grafana.com/docs/grafana-cloud/cost-management-and-billing/understand-your-invoice/logs-invoice/', 'Grafana Cloud docs: understand your logs invoice'),
    'grafana-metrics-invoice': s('https://grafana.com/docs/grafana-cloud/cost-management-and-billing/understand-your-invoice/metrics-invoice/', 'Grafana Cloud docs: understand your metrics invoice'),
    'loki-config': s('https://grafana.com/docs/loki/latest/configure/', 'Loki docs: configuration reference'),
    'loki-rate-limits': s('https://grafana.com/docs/loki/latest/operations/request-validation-rate-limits/', 'Loki docs: request validation and rate limits'),
    'loki-labels': s('https://grafana.com/docs/loki/latest/get-started/labels/bp-labels/', 'Loki docs: label best practices'),
    'mimir-config': s('https://grafana.com/docs/mimir/latest/configure/configuration-parameters/', 'Mimir docs: configuration parameters'),
    'mimir-runbooks': s('https://grafana.com/docs/mimir/latest/manage/mimir-runbooks/', 'Mimir docs: runbooks'),
    'tempo-config': s('https://grafana.com/docs/tempo/latest/configuration/', 'Tempo docs: configuration'),
    'otel-metrics-sdk': s('https://opentelemetry.io/docs/specs/otel/metrics/sdk/', 'OpenTelemetry specification: metrics SDK'),
    'otel-cardinality-blog': s('https://opentelemetry.io/blog/2026/cardinality-limits-in-opentelemetry/', 'OpenTelemetry blog: cardinality limits in OpenTelemetry', { published: '2026-08-06' }),
    'otel-sampling': s('https://opentelemetry.io/docs/concepts/sampling/', 'OpenTelemetry docs: sampling concepts', { updated: '2025-10-16' }),
    'otel-tail-sampling': s('https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/processor/tailsamplingprocessor/README.md', 'OpenTelemetry Collector: tail sampling processor README'),
    'otel-lb-exporter': s('https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/exporter/loadbalancingexporter/README.md', 'OpenTelemetry Collector: load-balancing exporter README'),
    'otel-memory-limiter': s('https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/processor/memorylimiterprocessor/README.md', 'OpenTelemetry Collector: memory limiter processor README'),
    'otel-batch': s('https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/main/processor/batchprocessor/README.md', 'OpenTelemetry Collector: batch processor README'),
    'otel-k8s-semconv': s('https://opentelemetry.io/blog/2026/k8s-semconv-rc/', 'OpenTelemetry blog: Kubernetes semantic conventions release candidate', { published: '2026-03-16' }),
    'otel-span-events': s('https://opentelemetry.io/blog/2026/deprecating-span-events/', 'OpenTelemetry blog: deprecating span events', { published: '2026-03-17' }),
    'otel-kubecon-recap': s('https://bindplane.com/blog/kubecon-europe-2026-opentelemetry-recap-from-amsterdam', 'Bindplane blog: KubeCon Europe 2026 OpenTelemetry recap', { published: '2026-04-02' }),
    'azure-monitor-limits': s('https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits', 'Microsoft Learn: Azure Monitor service limits', { updated: '2026-01-19' }),
    'azure-prom-troubleshoot': s('https://learn.microsoft.com/en-us/azure/azure-monitor/containers/prometheus-metrics-troubleshoot', 'Microsoft Learn: troubleshoot managed Prometheus collection', { updated: '2025-06-19' }),
    'azure-prom-overview': s('https://learn.microsoft.com/en-us/azure/azure-monitor/metrics/prometheus-metrics-overview', 'Microsoft Learn: Azure Monitor managed service for Prometheus', { updated: '2026-07-07' }),
    'azure-codeless': s('https://learn.microsoft.com/en-us/azure/azure-monitor/app/kubernetes-codeless', 'Microsoft Learn: Kubernetes codeless OpenTelemetry autoinstrumentation', { updated: '2026-06-25' }),
    'azure-fleet-networking': s('https://learn.microsoft.com/en-us/azure/kubernetes-fleet/concepts-cross-cluster-networking', 'Microsoft Learn: Fleet Manager cross-cluster networking (preview)', { updated: '2026-05-22' }),
    'azure-sre-agent-ga': s('https://techcommunity.microsoft.com/blog/appsonazureblog/announcing-general-availability-for-the-azure-sre-agent/4500682', 'Microsoft Tech Community: Azure SRE Agent general availability', { published: '2026-03-10' }),
    'ms-kubecon-2026': s('https://opensource.microsoft.com/blog/2026/03/24/whats-new-with-microsoft-in-open-source-and-kubernetes-at-kubecon-cloudnativecon-europe-2026/', "Microsoft Open Source blog: what's new at KubeCon Europe 2026", { published: '2026-03-24' }),
    'amp-quotas': s('https://docs.aws.amazon.com/prometheus/latest/userguide/AMP_quotas.html', 'Amazon Web Services (AWS) docs: Amazon Managed Service for Prometheus quotas'),
    'amp-pricing': s('https://aws.amazon.com/prometheus/pricing/', 'Amazon Managed Service for Prometheus pricing', { updated: '2026-09-25' }),
    'cloudwatch-pricing': s('https://aws.amazon.com/cloudwatch/pricing/', 'Amazon CloudWatch pricing', { updated: '2026-09-25' }),
    'gcp-pricing': s('https://cloud.google.com/stackdriver/pricing', 'Google Cloud Observability pricing'),
    'holmesgpt-cncf': s('https://www.cncf.io/blog/2026/01/07/holmesgpt-agentic-troubleshooting-built-for-the-cloud-native-era/', 'Cloud Native Computing Foundation (CNCF) blog: HolmesGPT, agentic troubleshooting', { published: '2026-01-07' }),
    'holmesgpt-benchmark': s('https://holmesgpt.dev/latest/development/evaluations/history/frontier_5_models_20260314_204516/', 'HolmesGPT docs: evaluation run of five frontier models', { published: '2026-03-14' }),
    'solo-agentevals': s('https://solo.io/press-releases/introducing-new-agentic-open-source-project-agentevals', 'Solo.io press release: agentevals', { published: '2026-03-25' })
  };

  function row(text, sourceIds, reasoning) { return { text: text, sourceIds: sourceIds || [], reasoning: !!reasoning }; }
  function price(id, label, unit, usd, basis, sourceId) { return { id: id, label: label, unit: unit, usd: usd, basis: basis, sourceId: sourceId }; }
  function limit(id, text, value, sourceId) { return { id: id, text: text, value: value, sourceId: sourceId }; }

  // ------------------------------------------------------------------------------------------
  // The four stacks
  // ------------------------------------------------------------------------------------------
  var stacks = [
    {
      id: 'datadog',
      name: 'Datadog',
      tagline: 'One hosted platform for metrics, logs and traces, priced per host plus usage.',
      rows: {
        shows: row('Logs are searchable once they are indexed. If an index has a daily quota and a log storm uses it up, newer lines still reach live tail and the archives but stop being indexed until the quota resets, at 2:00 pm UTC unless you change it.', ['dd-log-indexes']),
        correlate: row('The Agent samples traces toward about 10 traces per second overall and adds an error sampler that keeps as many as 10 extra error traces a second on each Agent. Spans stay searchable for 15 days only if a retention filter keeps them; live search covers the last 15 minutes.', ['dd-trace-ingestion', 'dd-trace-retention', 'dd-pricing']),
        multicluster: row('Kubernetes Explorer joins data from the Datadog Agent and from OpenTelemetry across clusters. Reading OpenTelemetry data directly is a preview, first shown on March 23, 2026.', ['dd-otel-k8s-explorer', 'dd-otel-news']),
        ai: row('No Datadog AI troubleshooting feature was verified for this comparison, so this column claims none. Check the current Datadog docs before you count on one.', [], true)
      },
      prices: [
        price('dd-infra-pro', 'Infrastructure Pro', 'per host per month, billed annually', 15, 'Starting price; $18 on-demand.', 'dd-pricing'),
        price('dd-infra-ent', 'Infrastructure Enterprise', 'per host per month, billed annually', 23, 'Starting price; $27 on-demand.', 'dd-pricing'),
        price('dd-apm', 'Application Performance Monitoring (APM), with Infrastructure', 'per host per month, billed annually', 31, 'Starting price; $48 on-demand. APM Pro from $35 and APM Enterprise from $40 per host.', 'dd-pricing'),
        price('dd-apm-span-overage', 'Ingested spans above the APM allotment', 'per GB, in the hour it happens', 0.10, 'Every APM host brings a monthly allowance of 150 GB of spans ingested and 1 million spans indexed; the ingested allowance is checked hour by hour, pooled across APM hosts.', 'dd-pricing'),
        price('dd-log-ingest', 'Log ingestion', 'per GB ingested, measured uncompressed', 0.10, 'Starting price, charged on bytes.', 'dd-pricing'),
        price('dd-log-index', 'Log indexing, 15-day retention', 'for each million log events a month, on annual billing', 1.70, 'Standard indexing; $2.55 on-demand. Charged per event, not per GB.', 'dd-pricing'),
        price('dd-custom-metrics-overage', 'Custom metrics above the included amount', 'per custom metric', null, 'Billed on usage; Datadog does not publish the rate and points you to sales.', 'dd-pricing')
      ],
      limits: [
        limit('dd-custom-included', 'Custom metrics included per host, pooled across the account (Pro / Enterprise)', '100 / 200', 'dd-pricing'),
        limit('dd-custom-definition', 'What counts as one custom metric', 'a metric name plus one set of tag values, host included', 'dd-custom-metrics'),
        limit('dd-index-reset', 'Log index daily quota reset', '2:00 pm UTC by default', 'dd-log-indexes'),
        limit('dd-agent-target', 'Agent trace sampling target', 'about 10 traces per second overall', 'dd-trace-ingestion'),
        limit('dd-error-sampler', 'Error sampler', 'at most 10 error traces a second on each Agent', 'dd-trace-ingestion'),
        limit('dd-sdk-rules', 'Your own sampling rules in a tracing library', 'capped at 100 traces a second for each service instance unless you set DD_TRACE_RATE_LIMIT', 'dd-trace-ingestion'),
        limit('dd-retention', 'Indexed spans stay searchable', '15 days, only for spans a retention filter keeps', 'dd-trace-retention'),
        limit('dd-live-search', 'Live trace search window', '15 minutes', 'dd-pricing'),
        limit('dd-apm-allotment', 'Ingested spans included per APM host', '150 GB a month, checked hour by hour', 'dd-pricing')
      ]
    },
    {
      id: 'grafana',
      name: 'Grafana (self-hosted LGTM or Grafana Cloud)',
      tagline: 'Loki for logs, Grafana for dashboards, Tempo for traces and Mimir for metrics (LGTM), run yourself or bought as Grafana Cloud.',
      rows: {
        shows: row('With the self-hosted defaults, Loki accepts 5,000 active streams per tenant and Mimir 150,000 series per tenant. Mimir drops series above its limit with a client (4xx) error that senders do not retry, so those series stay missing; Loki refuses only new streams and keeps the existing ones flowing.', ['loki-config', 'loki-rate-limits', 'mimir-config', 'mimir-runbooks']),
        correlate: row('Trace size and rate have default caps: Tempo refuses a trace over 5 MB (TRACE_TOO_LARGE) and partly drops oversized traces at compaction, and each distributor accepts 30 MB per second. Grafana Cloud bills logs and traces per GB processed and written, so keeping more traces during an incident costs more.', ['tempo-config', 'grafana-pricing']),
        multicluster: row('Self-hosted limits apply per tenant, so clusters that write into one tenant share its 150,000-series and 5,000-stream defaults. Grafana Cloud hosted per-tenant limits were not verified for this comparison.', ['mimir-config', 'loki-config'], true),
        ai: row("No Grafana AI assistant was verified for this comparison. HolmesGPT's own March 2026 benchmark found questions that need historical logs from Loki were its weakest area (10% to 40% of runs passed), so treat any agent's conclusions from old logs with care.", ['holmesgpt-benchmark'])
      },
      prices: [
        price('grafana-pro-fee', 'Grafana Cloud Pro platform fee', 'per month', 19, 'Covers 10k active series plus 50 GB each of logs and traces every month.', 'grafana-pricing'),
        price('grafana-metrics', 'Grafana Cloud metrics above 10k series', 'per 1,000 active series per month', 6.50, 'Starting price. Billed on the higher of active series or data points per minute, at the 95th percentile of the month. Enterprise from $3 per 1,000 series with a $25,000 yearly minimum.', 'grafana-pricing'),
        price('grafana-logs-process', 'Grafana Cloud logs processed', 'per GB that arrives', 0.05, 'Starting price, charged on everything that arrives, before any dropping.', 'grafana-pricing'),
        price('grafana-logs-write', 'Grafana Cloud logs written', 'per GB stored', 0.40, 'Starting price; the first 50 GB written each month is included.', 'grafana-pricing'),
        price('grafana-logs-retain', 'Grafana Cloud log retention beyond 30 days', 'per GB for each extra 30 days', 0.10, 'Starting price; paid plans keep 30 days at no extra charge.', 'grafana-pricing'),
        price('grafana-traces-process', 'Grafana Cloud traces processed', 'per GB that arrives', 0.05, 'Starting price.', 'grafana-pricing'),
        price('grafana-traces-write', 'Grafana Cloud traces written', 'per GB stored', 0.40, 'Starting price.', 'grafana-pricing'),
        price('grafana-selfhosted', 'Self-hosted Loki, Mimir and Tempo', 'your own compute and storage', null, 'No list price: you pay for the infrastructure you run.', null)
      ],
      limits: [
        limit('loki-labels', 'Loki: label names per series (self-hosted default)', '15', 'loki-config'),
        limit('loki-streams', 'Loki: active streams per tenant (self-hosted default)', '5,000; requests that would add streams get HTTP 429', 'loki-config'),
        limit('loki-rate', 'Loki: ingestion rate per tenant (self-hosted default)', '4 MB/s, 6 MB burst', 'loki-config'),
        limit('loki-line', 'Loki: longest log line (self-hosted default)', '256 KB; longer lines are dropped unless truncation is on', 'loki-config'),
        limit('loki-guidance', 'Loki: active streams guidance for one tenant', 'stay under 100,000, even for tenants sending over 10 TB a day', 'loki-labels'),
        limit('mimir-series', 'Mimir: series per tenant (self-hosted default)', '150,000; excess discarded with a 4xx error', 'mimir-config'),
        limit('mimir-rate', 'Mimir: samples per second per tenant (self-hosted default)', '10,000, burst 200,000', 'mimir-config'),
        limit('tempo-trace', 'Tempo: largest trace (default)', '5 MB', 'tempo-config'),
        limit('tempo-rate', 'Tempo: ingestion per distributor (default)', '30 MB/s', 'tempo-config'),
        limit('tempo-live', 'Tempo: live traces per tenant per instance (default)', '10,000', 'tempo-config'),
        limit('gc-active', 'Grafana Cloud: when a series counts as active', 'data in the last 20 minutes; billed at the 95th percentile', 'grafana-metrics-invoice'),
        limit('gc-free', 'Grafana Cloud free tier', '10k series, 50 GB logs, 50 GB traces, 14-day retention', 'grafana-pricing'),
        limit('gc-retention', 'Grafana Cloud Pro retention', '13 months for metrics, 30 days for logs and traces', 'grafana-pricing'),
        limit('gc-pricing-change', 'Grafana Cloud pricing page', 'says the pricing model is changing; treat these prices as subject to change', 'grafana-pricing')
      ]
    },
    {
      id: 'otel',
      name: 'OpenTelemetry + a backend of your choice',
      tagline: 'Vendor-neutral software development kits (SDKs) and a Collector that send OpenTelemetry Protocol (OTLP) data to any backend; the backend you pick sets the bill.',
      rows: {
        shows: row('Errors reach you only if their trace was kept. Head sampling decides before a request finishes, so it cannot promise to keep every trace with an error; tail sampling can, but needs every span of a trace on one Collector. In a telemetry spike, the Collector memory limiter refuses data above its soft limit, and data the sender does not retry is lost.', ['otel-sampling', 'otel-tail-sampling', 'otel-memory-limiter']),
        correlate: row('New events and exceptions are meant to be logs tied to the active span (the span event API began its deprecation on March 17, 2026). The standard Kubernetes attribute names reached release candidate on March 16, 2026 behind Collector feature gates, and Collector 0.147.0 and 0.148.0 changed metric units to singular, so dashboards that match old names or unit text can go blank after an upgrade.', ['otel-span-events', 'otel-k8s-semconv', 'dd-otel-news']),
        multicluster: row("Each cluster's Collector stamps its own Kubernetes attributes and forwards to one backend, so a fleet view is only as consistent as those Collector settings and versions. How the clusters are then compared depends on the backend you choose.", ['otel-k8s-semconv'], true),
        ai: row('OpenTelemetry carries the data, not the diagnosis; an agent sits on top. HolmesGPT can run its model on your own machine, in the cluster or in the cloud, and Solo.io agentevals (March 2026) uses OpenTelemetry to record and score what an agent did.', ['holmesgpt-cncf', 'solo-agentevals'])
      },
      prices: [
        price('cw-otel-metrics', 'Example backend: Amazon CloudWatch OpenTelemetry metrics', 'per GB ingested, measured on the uncompressed OTLP payload', 0.50, 'Includes 15 months of storage; no charge per unique series. AWS sizes a data point carrying 10 to 15 attributes at 300 to 600 bytes.', 'cloudwatch-pricing'),
        price('cw-container-insights-otel', 'Example backend: Container Insights with OpenTelemetry for Amazon EKS', 'per GB ingested', 0.08, 'Query charges apply separately.', 'cloudwatch-pricing')
      ],
      limits: [
        limit('otel-sdk-cap', 'Metrics SDK cardinality limit (specification default)', '2,000 attribute combinations per metric, per process; the rest merge into one overflow series', 'otel-metrics-sdk'),
        limit('otel-overflow', 'What the cap does not do', 'put any ceiling on the total series your backend receives', 'otel-cardinality-blog'),
        limit('otel-tail-wait', 'Tail sampling decision wait (default)', '30 seconds', 'otel-tail-sampling'),
        limit('otel-tail-traces', 'Traces held for tail sampling (default)', '50,000; beyond that some are dropped before a decision', 'otel-tail-sampling'),
        limit('otel-lb-routing', 'Load-balancing exporter', 'routes traces by trace ID; does not retry another endpoint by default', 'otel-lb-exporter'),
        limit('otel-memory-limiter', 'Collector memory limiter', 'refuses data above the soft limit; forces garbage collection above the hard limit', 'otel-memory-limiter'),
        limit('otel-batch', 'Batch processor defaults', '8,192 items or 200 ms; place it after the memory limiter and any sampling', 'otel-batch'),
        limit('otel-units', 'Collector 0.147.0 and 0.148.0', 'metric units changed to singular, for example {request}', 'dd-otel-news'),
        limit('otel-injector', 'OpenTelemetry Injector (zero-code)', 'alpha, per the KubeCon project update recap', 'otel-kubecon-recap')
      ]
    },
    {
      id: 'hosted',
      name: 'Hosted cloud (Azure Monitor, Amazon or Google managed Prometheus)',
      tagline: 'Your cloud provider runs Prometheus-compatible metric storage for you; logs and traces live in separate services.',
      rows: {
        shows: row('Metrics land in a managed Prometheus workspace with per-workspace limits. Azure allows 1,000,000 active series (counted over about 12 hours) and throttles once limits are reached; Amazon allows 50,000,000 but can throttle a sudden jump; Google bills every sample.', ['azure-monitor-limits', 'azure-prom-troubleshoot', 'amp-quotas', 'gcp-pricing']),
        correlate: row('Logs and traces are separate services in each cloud and are not priced here. On Azure Kubernetes Service (AKS), the codeless OpenTelemetry option sends app traces to Application Insights and needs the deployments restarted.', ['azure-codeless'], true),
        multicluster: row("Clusters that write to one workspace share its limits. On Azure, Fleet Manager can now connect clusters over a Cilium ClusterMesh that Microsoft runs, a preview for up to 255 clusters that the docs say is not for production.", ['azure-monitor-limits', 'azure-fleet-networking', 'ms-kubecon-2026'], true),
        ai: row("Azure SRE Agent reached general availability on March 10, 2026; you set how far it may act on its own, from suggestions up to automatic responses inside guardrails. Microsoft's KubeCon post also describes agentic container networking on Azure Kubernetes Service (AKS), which turns plain-language questions into read-only network checks. No equivalent was verified for Amazon or Google in this research.", ['azure-sre-agent-ga', 'ms-kubecon-2026'])
      },
      prices: [
        price('azure-prom', 'Azure Monitor managed service for Prometheus', 'billed on ingestion and query', null, 'Storage for 18 months is free; per-sample prices were not verified.', 'azure-prom-overview'),
        price('amp-example', 'Amazon Managed Service for Prometheus (pricing page example)', 'per 10 million samples, first 2 billion', 0.90, 'The page labels this an example and names no region; rates above 2 billion samples were not captured.', 'amp-pricing'),
        price('gmp-tier-1', 'Google Cloud Managed Service for Prometheus, first 50 billion samples', 'per million samples', 0.06, 'Effective August 8, 2023. A histogram point counts 2 samples plus 1 per non-empty bucket.', 'gcp-pricing'),
        price('gmp-tier-2', 'Google Cloud Managed Service for Prometheus, 50 to 250 billion', 'per million samples', 0.048, '', 'gcp-pricing'),
        price('gmp-tier-3', 'Google Cloud Managed Service for Prometheus, 250 to 500 billion', 'per million samples', 0.036, '', 'gcp-pricing'),
        price('gmp-tier-4', 'Google Cloud Managed Service for Prometheus, above 500 billion', 'per million samples', 0.024, '', 'gcp-pricing'),
        price('cw-classic-example', 'Amazon CloudWatch classic metrics (pricing page example)', 'per metric, first 10,000', 0.30, 'From a worked example; volume tiers apply above 10,000 metrics.', 'cloudwatch-pricing')
      ],
      limits: [
        limit('azure-series', 'Azure: active series per workspace', '1,000,000 (reported in about the last 12 hours); can be raised on request', 'azure-monitor-limits'),
        limit('azure-events', 'Azure: events ingested per minute per workspace', '1,000,000; can be raised on request', 'azure-monitor-limits'),
        limit('azure-dcr', 'Azure: per data collection rule (DCR)', '15,000 requests and 50 GB a minute; cannot be raised', 'azure-monitor-limits'),
        limit('azure-query', 'Azure: query range and retention', '32 days per query; data kept 18 months', 'azure-monitor-limits'),
        limit('azure-utilization', 'Azure: metric to alert on', 'Active Time Series % Utilization', 'azure-prom-troubleshoot'),
        limit('amp-series', 'Amazon: active series per workspace', '50,000,000 (a sample in the last 2 hours); up to 1.5 billion on request', 'amp-quotas'),
        limit('amp-burst', 'Amazon: burst rule', 'may throttle when series double or grow 10 million over the last 30 minutes; never below 2 million series', 'amp-quotas'),
        limit('amp-rate', 'Amazon: ingestion rate', '1/30 of the series quota, capped at 1,666,666 samples a second', 'amp-quotas'),
        limit('amp-signal', 'Amazon: how throttling shows up', 'DiscardedSamples with reason rate_limited, in CloudWatch', 'amp-quotas'),
        limit('gmp-histogram', 'Google: histogram cost', '2 samples per point plus 1 per non-empty bucket', 'gcp-pricing'),
        limit('fleet-networking', 'Azure Fleet Manager cross-cluster networking (preview)', 'up to 255 clusters, one network per cluster, Kubernetes 1.32 or later, no overlay network', 'azure-fleet-networking')
      ]
    }
  ];

  // ------------------------------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------------------------------
  function fmtInt(n) { return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
  function fmtNum(n) { return n >= 100 ? fmtInt(n) : String(Math.round(n * 10) / 10); }
  function money(n) { return n >= 100 ? Math.round(n) : Math.round(n * 100) / 100; }
  function plural(n, one, many) { return n === 1 ? one : many; }

  // Scale inputs may arrive as strings from <input> elements; blanks, NaN and negatives fall back.
  function toNum(v, d) {
    if (v == null) return d;
    if (typeof v === 'string') { v = v.replace(/[,_\s]/g, ''); if (v === '') return d; }
    var n = Number(v);
    return isFinite(n) && n >= 0 ? n : d;
  }
  function normScale(scale) {
    scale = scale && typeof scale === 'object' ? scale : {};
    return {
      nodes: Math.round(toNum(scale.nodes, DEFAULT_SCALE.nodes)),
      logsGbPerDay: toNum(scale.logsGbPerDay, DEFAULT_SCALE.logsGbPerDay),
      activeSeries: Math.round(toNum(scale.activeSeries, DEFAULT_SCALE.activeSeries)),
      apmHosts: Math.round(toNum(scale.apmHosts, DEFAULT_SCALE.apmHosts))
    };
  }

  // Alert label keys that name a pod, node, container or address (per instance) versus ones that
  // name a request, user or session (per request). The OpenTelemetry SDK cap bites on the second kind.
  var INFRA_LABEL = /^(pod|pod_name|pod_ip|pod_uid|kubernetes_pod_name|exported_pod|instance|exported_instance|container|container_id|container_name|node|nodename|node_name|kubernetes_node|host|hostname|host_ip|ip|address|endpoint)$/i;

  function shortComponent(id) {
    var s2 = String(id);
    var rest = s2.indexOf(':') >= 0 ? s2.slice(s2.indexOf(':') + 1) : s2;
    var parts = rest.split('/');
    var name = parts[parts.length - 1] || rest;
    return parts.length >= 3 && parts[0] ? name + ' (' + parts[0] + ')' : name;
  }

  function normTraits(tr) {
    tr = tr && typeof tr === 'object' ? tr : {};
    var clusters = Array.isArray(tr.clusters) ? tr.clusters.filter(Boolean).map(String) : [];
    var clusterCount = Math.max(Math.round(toNum(tr.clusterCount, 0)), clusters.length);
    var seen = {};
    var hc = (Array.isArray(tr.highCardinalityLabels) ? tr.highCardinalityLabels : [])
      .filter(function (k) { return k != null && String(k) !== ''; })
      .map(String)
      .filter(function (k) { if (seen[k]) return false; seen[k] = true; return true; });
    var src = tr.sources && typeof tr.sources === 'object' ? tr.sources : {};
    var spanCount = toNum(tr.spanCount, 0);
    var llpm = tr.logLinesPerMin == null ? null : toNum(tr.logLinesPerMin, null);
    return {
      clusterCount: clusterCount,
      multi: !!tr.multiCluster || clusterCount >= 2,
      failingClusterCount: Math.round(toNum(tr.failingClusterCount, 0)),
      hc: hc,
      hcInfra: hc.filter(function (k) { return INFRA_LABEL.test(k); }),
      hcRequest: hc.filter(function (k) { return !INFRA_LABEL.test(k); }),
      etm: !!tr.errorTracesMissing,
      logLinesPerMin: llpm,
      untraced: (Array.isArray(tr.untracedFailingComponents) ? tr.untracedFailingComponents : []).filter(Boolean).map(String),
      hasLogs: !!src.logs,
      hasTraces: !!src.traces || spanCount > 0
    };
  }

  function hcList(t) { return t.hc.join(', '); }
  function hcAdj(t) {
    if (t.hcRequest.length) return 'per-request';
    return t.hcInfra.some(function (k) { return /pod/i.test(k); }) ? 'per-pod' : 'per-instance';
  }
  function clusterPhrase(t) {
    return 'This incident spans ' + t.clusterCount + ' clusters' +
      (t.failingClusterCount ? ' (' + t.failingClusterCount + ' failing)' : '') + '.';
  }
  function pasteRate(t) {
    // A pasted excerpt (grep, tail) says nothing about production volume; say so rather than imply it.
    return t.logLinesPerMin ? ' The excerpt you pasted holds about ' + fmtNum(t.logLinesPerMin) + ' log lines a minute; that is the excerpt, not your real volume.' : '';
  }

  function flag(level, text, because, sourceIds, reasoning) {
    return { level: level, text: text, because: because, sourceIds: sourceIds || [], reasoning: !!reasoning };
  }
  function cost(label, monthlyUsd, basis, sourceId, priceId) {
    return { label: label, monthlyUsd: monthlyUsd == null ? null : money(monthlyUsd), basis: basis, sourceId: sourceId || null, priceId: priceId || null };
  }

  var LIST = 'List price, before discounts, 30-day month.';

  // ------------------------------------------------------------------------------------------
  // Datadog
  // ------------------------------------------------------------------------------------------
  function datadogFit(t, sc) {
    var f = [];
    var allot = sc.nodes * 100;
    if (t.hc.length) {
      f.push(flag('strain',
        (hcAdj(t) === 'per-pod' ? 'Per-pod' : hcAdj(t) === 'per-request' ? 'Per-request' : 'Per-instance') + ' tags turn into custom metrics billed at a rate Datadog does not publish',
        'Your alerts carry per-instance labels (' + hcList(t) + '). Datadog counts a metric name plus each set of tag values, host included, as one custom metric, so every new value adds more. ' +
          fmtInt(sc.nodes) + ' hosts on Infrastructure Pro include ' + fmtInt(allot) + ' custom metrics, pooled across the account' +
          (sc.activeSeries > allot ? '; if your ' + fmtInt(sc.activeSeries) + ' series reach Datadog as custom metrics, the excess is billed on usage at a rate you have to get from sales.' : '; anything above that is billed on usage at a rate you have to get from sales.'),
        ['dd-custom-metrics', 'dd-pricing'], true));
    } else if (sc.activeSeries > allot) {
      f.push(flag('strain', 'Your series count is far above the custom metrics included with your hosts',
        fmtInt(sc.nodes) + ' hosts on Infrastructure Pro include ' + fmtInt(allot) + ' custom metrics, pooled across the account. If your ' + fmtInt(sc.activeSeries) + ' series reach Datadog as custom metrics, the excess is billed on usage at a rate Datadog does not publish.',
        ['dd-pricing', 'dd-custom-metrics'], true));
    } else {
      f.push(flag('ok', 'Your series fit inside the custom metrics included with your hosts',
        fmtInt(sc.activeSeries) + ' series against ' + fmtInt(allot) + ' included (' + fmtInt(sc.nodes) + ' hosts x 100 on Infrastructure Pro, pooled), assuming each series counts as one custom metric.',
        ['dd-pricing'], true));
    }
    if (t.etm) {
      f.push(flag('ok', 'An error sampler would likely keep some of the error traces this incident may be missing',
        'A failing service here logged errors but sent no error spans, and no caller recorded the failures either: the pattern head sampling can leave behind. Besides aiming for about 10 traces per second overall, the Datadog Agent runs an error sampler that can keep as many as 10 error traces a second on each Agent, so some error traces survive even when head sampling drops them.',
        ['dd-trace-ingestion'], true));
      f.push(flag('strain', 'Turning trace sampling up to catch the errors is billed by the hour',
        'Each APM host includes 150 GB of ingested spans a month, checked hour by hour across all APM hosts. Spread evenly over a 730-hour month that is about 0.2 GB per host per hour, so about ' + fmtNum(sc.apmHosts * 0.205) + ' GB an hour for your ' + fmtInt(sc.apmHosts) + ' APM hosts (our arithmetic, not a published figure). Spans above that in any hour cost $0.10 per GB, even if the rest of the month is quiet.',
        ['dd-pricing'], true));
    }
    if (t.hasTraces || t.etm) {
      f.push(flag('strain', 'Spans that no retention filter keeps drop out of search after 15 minutes',
        'Live trace search covers the last 15 minutes. After that, only spans kept by a retention filter (searchable for 15 days) or by the always-on intelligent filter can be found, so add filters for your critical services before the next incident.',
        ['dd-pricing', 'dd-trace-retention']));
    }
    if (t.hasLogs) {
      f.push(flag('strain', 'A daily index quota can stop log indexing in the middle of the incident',
        'This incident\'s evidence includes logs.' + pasteRate(t) + ' If an index has a daily quota and a burst of repeated lines uses it up, new logs still reach live tail and the archives but stop being indexed until the quota resets (2:00 pm UTC by default). At ' + fmtNum(sc.logsGbPerDay) + ' GB a day, give noisy sources their own index and quota.',
        ['dd-log-indexes'], true));
    }
    if (t.multi) {
      f.push(flag('ok', 'Kubernetes Explorer can put the clusters side by side',
        clusterPhrase(t) + ' Kubernetes Explorer joins Datadog Agent data with OpenTelemetry data across clusters; reading OpenTelemetry data directly is a preview first shown on March 23, 2026.',
        ['dd-otel-k8s-explorer', 'dd-otel-news']));
    }

    var c = [];
    c.push(cost('Infrastructure Pro', sc.nodes * 15,
      fmtInt(sc.nodes) + ' hosts x $15 a host a month, the starting price on annual billing ($18 a month on demand). Assumes one Datadog host per Kubernetes node. ' + LIST,
      'dd-pricing', 'dd-infra-pro'));
    c.push(cost('APM (Application Performance Monitoring)', sc.apmHosts * 31,
      fmtInt(sc.apmHosts) + ' APM hosts x $31 a host a month, the starting price on annual billing when bought together with Infrastructure ($48 a month on demand). Each APM host brings an allowance of 150 GB of spans ingested and 1 million spans indexed. ' + LIST,
      'dd-pricing', 'dd-apm'));
    c.push(cost('Log ingestion', sc.logsGbPerDay * DAYS * 0.10,
      fmtNum(sc.logsGbPerDay) + ' GB a day x 30 days = ' + fmtInt(sc.logsGbPerDay * DAYS) + ' GB x $0.10 per GB ingested (starting price), measured uncompressed. ' + LIST,
      'dd-pricing', 'dd-log-ingest'));
    c.push(cost('Log indexing (15-day retention)', null,
      'From $1.70 for each million log events indexed in a month on annual billing ($2.55 on demand). It is charged per event, not per GB, and no verified figure turns your GB a day into an event count, so this line has no estimate.',
      'dd-pricing', 'dd-log-index'));
    if (sc.activeSeries > allot) {
      c.push(cost('Custom metrics above the included amount', null,
        fmtInt(sc.activeSeries) + ' series against ' + fmtInt(allot) + ' included (' + fmtInt(sc.nodes) + ' hosts x 100 on Infrastructure Pro, pooled). Datadog bills the extra on usage and does not publish the rate.',
        'dd-pricing', 'dd-custom-metrics-overage'));
    } else {
      c.push(cost('Custom metrics', 0,
        fmtInt(sc.activeSeries) + ' series fit within the ' + fmtInt(allot) + ' custom metrics included with your hosts (100 per host on Infrastructure Pro), assuming each series counts as one custom metric.',
        'dd-pricing', 'dd-infra-pro'));
    }
    return { flags: f, costLines: c };
  }

  // ------------------------------------------------------------------------------------------
  // Grafana (self-hosted LGTM or Grafana Cloud)
  // ------------------------------------------------------------------------------------------
  var MIMIR_SERIES = 150000, LOKI_RATE_MBS = 4;

  function grafanaFit(t, sc) {
    var f = [];
    if (sc.activeSeries > MIMIR_SERIES) {
      f.push(flag('strain', 'Self-hosted Mimir refuses series beyond 150,000 per tenant unless you raise the limit',
        'Your ' + fmtInt(sc.activeSeries) + ' active series are above the default per-tenant limit. Past it, Mimir discards the excess with a client (4xx) error that senders do not retry, so new series can go missing just when you compare the old and new versions.' +
          (t.hc.length ? ' Your ' + hcAdj(t) + ' labels (' + hcList(t) + ') add to it: each rollout or rollback brings new values while the old series still count.' : '') +
          ' Raise max_global_series_per_user before the next incident.',
        ['mimir-config', 'mimir-runbooks'], t.hc.length > 0));
    } else if (t.hc.length) {
      f.push(flag('strain', 'Per-instance labels can push a tenant past Mimir\'s 150,000-series default during a rollout',
        'Your alerts carry ' + hcAdj(t) + ' labels (' + hcList(t) + '). A rollout or rollback brings new values while the old series still count, and above 150,000 series per tenant Mimir discards the excess with a 4xx error that senders do not retry.',
        ['mimir-config', 'mimir-runbooks'], true));
    } else {
      f.push(flag('ok', 'Your series fit under self-hosted Mimir\'s default of 150,000 per tenant',
        'Your ' + fmtInt(sc.activeSeries) + ' active series are under the default per-tenant limit.',
        ['mimir-config']));
    }
    if (t.hc.length) {
      f.push(flag('strain', 'If these labels become Loki labels, new streams are refused past 5,000 per tenant',
        'Your alerts carry ' + hcAdj(t) + ' labels (' + hcList(t) + '). If your log shipper also makes them Loki labels, every new value opens new streams. With the default of 5,000 active streams per tenant, Loki answers requests that would add streams with HTTP 429 (retryable) while existing streams keep flowing, and during an ingester rollout even existing streams can be refused for a while. Keep such values out of labels and filter on them at query time.',
        ['loki-config', 'loki-rate-limits'], true));
    }
    var mbs = sc.logsGbPerDay * 1000 / 86400;
    if (mbs >= LOKI_RATE_MBS) {
      f.push(flag('strain', 'Your average log rate is above self-hosted Loki\'s default of 4 MB/s per tenant',
        'At ' + fmtNum(sc.logsGbPerDay) + ' GB a day you average about ' + fmtNum(mbs) + ' MB/s, above the 4 MB/s default (6 MB burst). Raise the ingestion rate and burst limits, or split tenants, before an incident adds a burst on top.' + pasteRate(t),
        ['loki-config']));
    } else if (mbs >= LOKI_RATE_MBS / 2) {
      f.push(flag('strain', 'An incident burst could reach self-hosted Loki\'s 4 MB/s default',
        'At ' + fmtNum(sc.logsGbPerDay) + ' GB a day you average about ' + fmtNum(mbs) + ' MB/s, at least half the 4 MB/s default (6 MB burst) per tenant. A log storm from crash-looping pods can double the rate.' + pasteRate(t),
        ['loki-config'], true));
    } else {
      f.push(flag('ok', 'Your average log rate is well under self-hosted Loki\'s 4 MB/s default',
        'At ' + fmtNum(sc.logsGbPerDay) + ' GB a day you average about ' + fmtNum(mbs) + ' MB/s against a default of 4 MB/s (6 MB burst) per tenant.' + pasteRate(t),
        ['loki-config']));
    }
    if (t.etm) {
      f.push(flag('strain', 'Tempo can only show the traces your sampler kept',
        'A failing service here logged errors but sent no error spans, and no caller recorded the failures, so its error traces may have been dropped before they reached Tempo. Keeping them needs tail sampling upstream in an OpenTelemetry Collector, with every span of a trace sent to the same Collector instance. In Grafana Cloud, keeping more traces also costs $0.05 per GB processed and $0.40 per GB written.',
        ['otel-sampling', 'otel-tail-sampling', 'grafana-pricing'], true));
    }
    if (t.multi) {
      f.push(flag('strain', 'Clusters that write into one tenant share its limits',
        clusterPhrase(t) + ' Self-hosted Loki and Mimir apply their stream and series limits per tenant, so clusters sharing a tenant share 5,000 streams and 150,000 series by default; separate tenants keep the limits apart but split your queries. Grafana Cloud hosted per-tenant limits were not verified for this comparison.',
        ['loki-config', 'mimir-config'], true));
    }
    if (t.hc.length) {
      f.push(flag('strain', 'Pod churn and faster scrapes can raise the Grafana Cloud metrics bill',
        'Grafana Cloud counts a series as active if it received data in the last 20 minutes and bills the higher of active series or data points per minute, at the 95th percentile of the month. A short rollout spike stays inside the top 5% and is ignored, but churn that lasts more than about 36 hours of a 30-day month, or a scrape interval shortened while debugging, shows up on the bill.',
        ['grafana-metrics-invoice'], true));
    }

    var gbMonth = sc.logsGbPerDay * DAYS;
    var c = [];
    c.push(cost('Grafana Cloud Pro platform fee', 19, '$19 a month, covering 10k active series plus 50 GB each of logs and traces. ' + LIST, 'grafana-pricing', 'grafana-pro-fee'));
    c.push(cost('Grafana Cloud metrics', Math.max(0, sc.activeSeries - 10000) / 1000 * 6.50,
      '(' + fmtInt(sc.activeSeries) + ' - 10,000 included) / 1,000 x $6.50 (starting price). Billed on the higher of active series or data points per minute at the 95th percentile, so scraping more often than once a minute raises it. ' + LIST,
      'grafana-pricing', 'grafana-metrics'));
    c.push(cost('Grafana Cloud logs processed', gbMonth * 0.05,
      fmtInt(gbMonth) + ' GB a month x $0.05 per GB that arrives (starting price), before any dropping. ' + LIST,
      'grafana-pricing', 'grafana-logs-process'));
    c.push(cost('Grafana Cloud logs written', Math.max(0, gbMonth - 50) * 0.40,
      '(' + fmtInt(gbMonth) + ' - 50 GB included) x $0.40 per GB written (starting price). Assumes nothing is dropped and 30-day retention; dropping lines cuts this line but not the processed one, and longer retention adds $0.10 per GB per extra 30 days. ' + LIST,
      'grafana-pricing', 'grafana-logs-write'));
    c.push(cost('Self-hosted Loki, Mimir and Tempo instead', null,
      'No list price: you pay for the compute and object storage you run. Check the default limits before you size it.',
      null, 'grafana-selfhosted'));
    return { flags: f, costLines: c };
  }

  // ------------------------------------------------------------------------------------------
  // OpenTelemetry + a backend of your choice
  // ------------------------------------------------------------------------------------------
  function otelFit(t, sc) {
    var f = [];
    if (t.etm) {
      f.push(flag('breaks', 'Head sampling may have dropped this incident\'s error traces',
        'A failing service here logged errors but sent no error spans, and no caller recorded the failures either. Head sampling decides when a request starts, so it cannot promise to keep traces that fail later. To keep them, run tail sampling in the Collector: every span of a trace has to reach the same Collector instance, so put a load-balancing exporter layer in front that routes by trace ID, and turn on its queue and retry, because by default it does not try another endpoint when delivery fails.' +
          (t.multi ? ' With ' + t.clusterCount + ' clusters, either keep each trace inside one cluster\'s Collectors or route every cluster through one shared layer; a trace split across Collectors is judged on partial data.' : ''),
        ['otel-sampling', 'otel-tail-sampling', 'otel-lb-exporter'], true));
    } else if (t.hasTraces) {
      f.push(flag('ok', 'Error spans reached your traces',
        'The failures show up as error spans, on the failing services or on the client spans of their callers, so sampling kept the traces you need here. Tail sampling (decision after 30 seconds by default, up to 50,000 traces held) keeps it that way under heavier load.',
        ['otel-tail-sampling'], true));
    }
    if (t.hcRequest.length) {
      f.push(flag('strain', 'Per-request labels hit the SDK limit of 2,000 combinations per metric',
        'Your alerts carry labels such as ' + t.hcRequest.join(', ') + '. When one process records more than 2,000 attribute combinations for a metric, the OpenTelemetry metrics SDK merges the rest into one series marked otel.metric.overflow=true: totals stay right, but breakdowns by label come up short. Alert on that marker and remove the leaking attribute.',
        ['otel-metrics-sdk', 'otel-cardinality-blog'], true));
    } else if (t.hcInfra.length) {
      f.push(flag('strain', 'Per-pod labels multiply series in your backend, and the SDK limit will not stop them',
        'Your alerts carry per-instance labels (' + hcList(t) + '). Each process reports only its own pod, so the SDK limit of 2,000 attribute combinations per metric rarely trips on them, and that limit puts no ceiling on the series your backend ends up storing. The backend\'s per-tenant or per-workspace limit is what applies; see the other columns.',
        ['otel-metrics-sdk', 'otel-cardinality-blog'], true));
    }
    if (t.untraced.length) {
      var names = t.untraced.slice(0, 3).map(shortComponent).join(', ') + (t.untraced.length > 3 ? ' and ' + (t.untraced.length - 3) + ' more' : '');
      f.push(flag('strain', t.untraced.length + ' failing ' + plural(t.untraced.length, 'component sends', 'components send') + ' no traces at all',
        names + ' failed in this incident but ' + plural(t.untraced.length, 'appears', 'appear') + ' in no trace, so that part of the path is dark. Zero-code instrumentation can add baseline traces: the OpenTelemetry Injector is alpha, and Azure\'s codeless option needs the deployment restarted and sends to Application Insights. Schedule that restart after the incident and record it as a change.',
        ['otel-kubecon-recap', 'azure-codeless'], true));
    }
    if (t.multi) {
      f.push(flag('strain', 'Every cluster\'s Collectors must label signals the same way',
        clusterPhrase(t) + ' Each cluster\'s Collector has to stamp the same cluster attribute on every signal, and the standard Kubernetes attribute names moved to release candidate in March 2026 behind opt-in feature gates, so Collectors on different versions or settings can name the same thing differently.',
        ['otel-k8s-semconv'], true));
    }
    f.push(flag('strain', 'Under load, the Collector refuses data, and senders that do not retry lose it',
      'Telemetry spikes during incidents. Above its soft limit the memory limiter refuses new data with a retryable error, and whatever the sender does not retry is lost. Size gateway Collectors for incident volume, not a quiet day, and alert on refused data.',
      ['otel-memory-limiter'], true));

    var bytesPerPoint = 450; // midpoint of the 300-600 bytes AWS gives for a point with 10-15 attributes
    var gb = sc.activeSeries * MINUTES_PER_MONTH * bytesPerPoint / 1e9;
    var lo = sc.activeSeries * MINUTES_PER_MONTH * 300 / 1e9, hi = sc.activeSeries * MINUTES_PER_MONTH * 600 / 1e9;
    var c = [];
    c.push(cost('Example backend: Amazon CloudWatch OpenTelemetry metrics', gb * 0.50,
      fmtInt(sc.activeSeries) + ' series x 1 point a minute (a 60-second interval) x about 450 bytes a point (AWS gives 300 to 600 bytes with 10 to 15 attributes) = about ' + fmtInt(gb) + ' GB x $0.50 per GB. The byte range alone moves it from about $' + fmtInt(lo * 0.5) + ' to $' + fmtInt(hi * 0.5) + '. No per-series charge. ' + LIST,
      'cloudwatch-pricing', 'cw-otel-metrics'));
    return { flags: f, costLines: c };
  }

  // ------------------------------------------------------------------------------------------
  // Hosted cloud (Azure Monitor, Amazon, Google managed Prometheus)
  // ------------------------------------------------------------------------------------------
  var AZURE_SERIES = 1000000, AMP_BURST_FLOOR = 2000000;
  var GMP_TIERS = [[50e9, 0.06], [200e9, 0.048], [250e9, 0.036], [Infinity, 0.024]];

  function gmpCost(samples) {
    var left = samples, total = 0;
    for (var i = 0; i < GMP_TIERS.length && left > 0; i++) {
      var take = Math.min(left, GMP_TIERS[i][0]);
      total += take / 1e6 * GMP_TIERS[i][1];
      left -= take;
    }
    return total;
  }

  function hostedFit(t, sc) {
    var f = [];
    var pct = Math.round(sc.activeSeries / AZURE_SERIES * 100);
    var churn = t.hc.length ? ' Your alerts carry ' + hcAdj(t) + ' labels (' + hcList(t) + '): Azure counts a series as active for about 12 hours after its last report, so every pod a rollout or rollback replaces stays on the count for half a day.' : '';
    var source = ' On AKS, Kubernetes custom resources now let you pick the container metrics you collect, one way to stay under it.';
    if (sc.activeSeries >= AZURE_SERIES) {
      f.push(flag('breaks', 'Azure: your series reach the 1,000,000 per-workspace default, where ingestion is throttled',
        'Your ' + fmtInt(sc.activeSeries) + ' active series meet or pass the default, and Azure throttles ingestion once its limits are reached, so new data can go missing mid-incident. Request an increase now and alert on Active Time Series % Utilization.' + churn + source,
        ['azure-monitor-limits', 'azure-prom-troubleshoot', 'ms-kubecon-2026'], t.hc.length > 0));
    } else if (pct >= 70 || t.hc.length) {
      f.push(flag('strain', pct >= 70 ? 'Azure: your series are close to the 1,000,000 per-workspace default' : 'Azure: pod churn counts against the 1,000,000-series workspace default for about 12 hours',
        'Your ' + fmtInt(sc.activeSeries) + ' active series are about ' + pct + '% of the per-workspace default, and Azure throttles once limits are reached.' + churn + ' Set an alert on the Active Time Series % Utilization metric and ask Microsoft for a higher limit ahead of time.' + source,
        ['azure-monitor-limits', 'azure-prom-troubleshoot', 'ms-kubecon-2026'], true));
    } else {
      f.push(flag('ok', 'Azure: your series sit well under the 1,000,000 per-workspace default',
        'Your ' + fmtInt(sc.activeSeries) + ' active series are about ' + pct + '% of the default. Alert on Active Time Series % Utilization so you see it coming.',
        ['azure-monitor-limits', 'azure-prom-troubleshoot']));
    }
    if (sc.activeSeries >= AMP_BURST_FLOOR) {
      f.push(flag('strain', 'Amazon: a sudden jump in series can be throttled long before the quota',
        'Above 2 million series, Amazon Managed Service for Prometheus may throttle when series double or grow by 10 million over the last 30 minutes, even far below its 50,000,000 default. Throttled samples show up as DiscardedSamples with reason rate_limited.' +
          (t.hc.length ? ' With ' + hcAdj(t) + ' labels, a large rollout or rollback is a likely trigger.' : ''),
        ['amp-quotas'], t.hc.length > 0));
    } else if (t.hc.length) {
      f.push(flag('ok', 'Amazon: no burst throttling below 2 million series',
        'With ' + fmtInt(sc.activeSeries) + ' series you are under the 2 million line where Amazon Managed Service for Prometheus starts applying its burst rule, so new pod series from a rollout are not throttled for arriving fast.',
        ['amp-quotas']));
    }
    if (t.hc.length) {
      f.push(flag('strain', 'Google: every extra series and histogram bucket is billed',
        'Google bills managed Prometheus per sample ($0.06 per million for the first 50 billion a month), and a histogram point counts 2 samples plus 1 for each non-empty bucket. ' + (hcAdj(t) === 'per-request' ? 'Per-request' : hcAdj(t) === 'per-pod' ? 'Per-pod' : 'Per-instance') + ' labels (' + hcList(t) + ') multiply both the series and the buckets.',
        ['gcp-pricing'], true));
    }
    if (t.etm) {
      f.push(flag('strain', 'Managed Prometheus keeps metrics only; error traces that may be missing depend on your tracing setup',
        'A failing service here logged errors but sent no error spans, and no caller recorded the failures either. The managed Prometheus services hold metrics, so keeping error traces still needs tail sampling in your own Collector. On AKS, the codeless OpenTelemetry option sends traces to Application Insights and needs the deployments restarted.',
        ['otel-tail-sampling', 'azure-codeless'], true));
    }
    if (t.multi) {
      f.push(flag('strain', 'Clusters that share a workspace share its limits',
        clusterPhrase(t) + ' Azure applies 1,000,000 active series and 1,000,000 events a minute per workspace and caps each data collection rule (DCR) at 15,000 requests and 50 GB a minute with no increase possible, so every cluster writing to one workspace or rule shares them. Azure Fleet Manager cross-cluster networking is a preview the docs say is not for production.',
        ['azure-monitor-limits', 'azure-fleet-networking'], true));
    }

    var samples = sc.activeSeries * MINUTES_PER_MONTH;
    var c = [];
    c.push(cost('Google Cloud Managed Service for Prometheus', gmpCost(samples),
      fmtInt(sc.activeSeries) + ' series x 1 sample a minute (a 60-second interval) = ' + fmtNum(samples / 1e9) + ' billion samples a month, at $0.06 per million for the first 50 billion and lower rates above. Histograms cost 2 samples plus 1 per non-empty bucket, so real bills run higher. ' + LIST,
      'gcp-pricing', 'gmp-tier-1'));
    c.push(cost('Amazon Managed Service for Prometheus', null,
      fmtNum(samples / 1e9) + ' billion samples a month at a 60-second interval. The pricing page gives only a worked example (the first 2 billion samples at $0.90 for every 10 million, region not named); the rates above that were not captured.',
      'amp-pricing', 'amp-example'));
    c.push(cost('Azure Monitor managed service for Prometheus', null,
      'Billed on ingestion and query, with 18 months of storage free. Per-sample prices were not verified for this comparison.',
      'azure-prom-overview', 'azure-prom'));
    return { flags: f, costLines: c };
  }

  // ------------------------------------------------------------------------------------------
  // stackFit
  // ------------------------------------------------------------------------------------------
  var LEVEL_ORDER = { breaks: 0, strain: 1, ok: 2 };

  function finish(r) {
    var flags = r.flags.map(function (x, i) { return { x: x, i: i }; })
      .sort(function (a, b) { return (LEVEL_ORDER[a.x.level] - LEVEL_ORDER[b.x.level]) || (a.i - b.i); })
      .map(function (o) { return o.x; });
    var breaks = flags.filter(function (x) { return x.level === 'breaks'; }).length;
    var strain = flags.filter(function (x) { return x.level === 'strain'; }).length;
    var verdict = breaks ? 'Strained' : strain >= 2 ? 'Workable' : 'Good fit';
    return { verdict: verdict, why: flags.length ? flags[0].text : '', flags: flags, costLines: r.costLines };
  }

  function stackFit(traits, scale) {
    var t = normTraits(traits);
    var sc = normScale(scale);
    return {
      datadog: finish(datadogFit(t, sc)),
      grafana: finish(grafanaFit(t, sc)),
      otel: finish(otelFit(t, sc)),
      hosted: finish(hostedFit(t, sc))
    };
  }
  stackFit.DEFAULT_SCALE = DEFAULT_SCALE;
  stackFit.normScale = normScale;

  WR.stacks = {
    asOf: AS_OF,
    sources: sources,
    stacks: stacks,
    scaleDefaults: DEFAULT_SCALE,
    costNote: 'Rough monthly estimates from list prices checked on ' + AS_OF + ', before discounts, for a 30-day month. "See pricing page" means the price was not verified or depends on a figure we could not verify.'
  };
  WR.stackFit = stackFit;
})(globalThis.WR = globalThis.WR || {});
