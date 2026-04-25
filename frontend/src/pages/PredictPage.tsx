import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Network, Server, Cpu, Play, X } from 'lucide-react'
import { PredictFormSchema, PREDICT_FORM_DEFAULTS, type PredictFormValues } from '@/types/forms'
import { usePredict, useLookupProtocols, useLookupServices, useLookupFlags, usePredictHistory } from '@/hooks'
import { FormInput, FormSelect, FormToggle, FieldGroup } from '@/components/form/index'
import { ActionButton } from '@/components/ui/index'
import { ConfidenceBar, RiskBadge, StatusBadge } from '@/components/ui/badges'
import { PageTabs } from '@/components/layout/PageTabs'
import type { PredictResponse } from '@/types/api'

export function PredictPage() {
  const predict        = usePredict()
  const predictHistory = usePredictHistory(50)
  const { data: protocols, isLoading: loadingProtocols } = useLookupProtocols()
  const { data: services,  isLoading: loadingServices  } = useLookupServices()
  const { data: flags,     isLoading: loadingFlags     } = useLookupFlags()

  const { register, handleSubmit, control, reset, formState: { errors, isValid } } =
    useForm<PredictFormValues>({
      resolver:      zodResolver(PredictFormSchema),
      defaultValues: PREDICT_FORM_DEFAULTS,
      mode:          'onChange',
    })

  const onSubmit = async (values: PredictFormValues) => {
    try {
      await predict.mutateAsync(values)
      await predictHistory.refetch()
    } catch {
      // Error toast handled by mutation's onError
    }
  }

  const lookupsLoading = loadingProtocols || loadingServices || loadingFlags

  return (
    <div className="flex flex-col gap-6 animate-fade-in">
      <PageTabs
        tabs={[
          { label: 'Network', to: '/connections' },
          { label: 'Predict', to: '/predict' },
          { label: 'Analytics', to: '/stats' },
        ]}
      />
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-xl tracking-wide text-text-primary uppercase">
            Threat Prediction Engine
          </h1>
          <p className="font-mono text-xs tracking-wider text-text-tertiary">
            MANUAL HEURISTIC OVERRIDE & DEEP PACKET INSPECTION ANALYSIS
          </p>
        </div>
        <div className="flex gap-2">
          <ActionButton variant="secondary" icon={<X size={14} />} onClick={() => reset(PREDICT_FORM_DEFAULTS)}>
            Clear Form
          </ActionButton>
          <ActionButton
            variant="primary"
            icon={<Play size={14} />}
            loading={predict.isPending}
            disabled={!isValid || lookupsLoading}
            onClick={handleSubmit(onSubmit)}
          >
            Run Prediction
          </ActionButton>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_340px]">

        {/* Left: form groups */}
        <form
          onSubmit={handleSubmit(onSubmit)}
          noValidate
          aria-label="Threat prediction form"
          className="flex flex-col gap-4"
        >
          {/* GROUP A — Network Metadata */}
          <FieldGroup title="Network Metadata" icon={<Network size={14} />}>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <FormInput label="Duration" name="duration" type="number" unit="sec"
                register={register('duration', { valueAsNumber: true })} error={errors.duration} required />
              <FormSelect label="Protocol Type" name="protocol_type"
                options={protocols?.values ?? []} loading={loadingProtocols}
                register={register('protocol_type')} error={errors.protocol_type} required />
              <FormSelect label="Service" name="service"
                options={services?.values ?? []} loading={loadingServices}
                register={register('service')} error={errors.service} required />
              <FormSelect label="Flag" name="flag"
                options={flags?.values ?? []} loading={loadingFlags}
                register={register('flag')} error={errors.flag} required />
              <FormInput label="Source Bytes" name="src_bytes" type="number" unit="bytes"
                register={register('src_bytes', { valueAsNumber: true })} error={errors.src_bytes} />
              <FormInput label="Destination Bytes" name="dst_bytes" type="number" unit="bytes"
                register={register('dst_bytes', { valueAsNumber: true })} error={errors.dst_bytes} />
              <Controller
                name="land"
                control={control}
                render={({ field }) => (
                  <FormToggle label="Land Attack" name="land"
                    checked={field.value} onChange={field.onChange}
                    helpText="Source and destination are the same host" />
                )}
              />
            </div>
          </FieldGroup>

          {/* GROUP B — Session State */}
          <FieldGroup title="Session State" icon={<Server size={14} />}>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Controller
                name="logged_in"
                control={control}
                render={({ field }) => (
                  <FormToggle label="Logged In" name="logged_in"
                    checked={field.value} onChange={field.onChange} />
                )}
              />
              <FormInput label="Connection Count" name="count" type="number"
                register={register('count', { valueAsNumber: true })} error={errors.count}
                helpText="Connections to same host in 2s window (0–511)" />
              <FormInput label="SRV Count" name="srv_count" type="number"
                register={register('srv_count', { valueAsNumber: true })} error={errors.srv_count} />
              <FormInput label="SYN Error Rate" name="serror_rate" type="number" step="0.01"
                register={register('serror_rate', { valueAsNumber: true })} error={errors.serror_rate}
                helpText="0.0 – 1.0" />
              <FormInput label="REJ Error Rate" name="rerror_rate" type="number" step="0.01"
                register={register('rerror_rate', { valueAsNumber: true })} error={errors.rerror_rate} />
              <FormInput label="Same Service Rate" name="same_srv_rate" type="number" step="0.01"
                register={register('same_srv_rate', { valueAsNumber: true })} error={errors.same_srv_rate} />
            </div>
          </FieldGroup>

          {/* GROUP C — Host-Based Features */}
          <FieldGroup title="Host-Based Features" icon={<Cpu size={14} />}>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <FormInput label="Dst Host Count" name="dst_host_count" type="number"
                register={register('dst_host_count', { valueAsNumber: true })} error={errors.dst_host_count}
                helpText="0–255" />
              <FormInput label="Dst Host SRV Count" name="dst_host_srv_count" type="number"
                register={register('dst_host_srv_count', { valueAsNumber: true })} error={errors.dst_host_srv_count} />
              <FormInput label="Same SRV Rate" name="dst_host_same_srv_rate" type="number" step="0.01"
                register={register('dst_host_same_srv_rate', { valueAsNumber: true })} error={errors.dst_host_same_srv_rate} />
              <FormInput label="Diff SRV Rate" name="dst_host_diff_srv_rate" type="number" step="0.01"
                register={register('dst_host_diff_srv_rate', { valueAsNumber: true })} error={errors.dst_host_diff_srv_rate} />
              <FormInput label="SYN Error Rate" name="dst_host_serror_rate" type="number" step="0.01"
                register={register('dst_host_serror_rate', { valueAsNumber: true })} error={errors.dst_host_serror_rate} />
            </div>
          </FieldGroup>
        </form>

        {/* Right: result panel */}
        <div className="flex flex-col gap-4">
          <ResultPanel result={predict.data} loading={predict.isPending} error={predict.error as any} />
        </div>
      </div>

      {/* Recent inferences */}
      {(predictHistory.data ?? []).length > 0 && (
        <section aria-label="Recent inferences">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-display text-xs tracking-wider text-text-secondary uppercase">
              Recent Inferences
            </h2>
            <span className="font-mono text-xs text-text-tertiary">
              LIVE_TICKER: {new Date().toISOString().substring(11, 19)} UTC
            </span>
          </div>
          <div className="rounded-lg border border-border bg-bg-surface overflow-x-auto">
            <table className="w-full" role="grid">
              <thead>
                <tr className="border-b border-border-strong">
                {['Timestamp', 'Type', 'Confidence', 'Status'].map(h => (
                    <th key={h} scope="col" className="px-4 py-2.5 text-left font-ui text-xs font-semibold tracking-wider text-text-secondary uppercase">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(predictHistory.data ?? []).map(r => (
                  <tr key={r.prediction_id} className="border-b border-border/50 hover:bg-bg-hover transition-colors">
                    <td className="px-4 py-3 font-mono text-sm text-text-code">{r.created_at}</td>
                    <td className="px-4 py-3">
                      <StatusBadge variant={r.prediction === 'Intrusion' ? 'critical' : 'authorized'} label={r.prediction} />
                    </td>
                    <td className="px-4 py-3">
                      <ConfidenceBar value={Math.max(0, Math.min(1, r.confidence))} size="sm" />
                    </td>
                    <td className="px-4 py-3">
                      <RiskBadge level={r.prediction === 'Intrusion' ? (r.confidence > 0.8 ? 'high' : r.confidence > 0.6 ? 'medium' : 'low') : 'normal'} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}

// ── Result Panel ──────────────────────────────────────────────
function ResultPanel({
  result, loading, error,
}: {
  result?:  PredictResponse | null
  loading:  boolean
  error?:   { message: string } | null
}) {
  if (loading) {
    return (
      <div className="rounded-lg border border-border bg-bg-surface p-5 flex flex-col gap-4">
        <div className="skeleton h-6 w-32 rounded-sm" />
        <div className="skeleton h-10 w-20 rounded-sm" />
        <div className="skeleton h-2 w-full rounded-full" />
        {Array.from({ length: 5 }, (_, i) => (
          <div key={i} className="flex items-center gap-3">
            <div className="skeleton h-3 w-24 rounded-sm" />
            <div className="skeleton h-2 flex-1 rounded-full" />
          </div>
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-lg border border-critical/30 bg-critical/5 p-5 flex flex-col items-center gap-3 text-center">
        <p className="font-display text-sm tracking-wide text-critical uppercase">Analysis Failed</p>
        <p className="font-mono text-xs text-text-tertiary">{error.message}</p>
      </div>
    )
  }

  if (!result) {
    return (
      <div className="rounded-lg border border-border bg-bg-surface p-5 flex flex-col items-center justify-center gap-3 text-center min-h-[220px]">
        <div className="text-text-tertiary">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
        </div>
        <p className="font-display text-base tracking-wide text-text-secondary uppercase">Ready for Analysis</p>
        <p className="font-ui text-xs text-text-tertiary max-w-[200px]">
          Input network parameters and execute 'Run Prediction' to generate threat scores.
        </p>
        {/* Placeholder bars */}
        <div className="mt-2 flex items-end gap-1.5 h-12">
          {[30, 50, 70, 40, 60, 45, 80, 35].map((h, i) => (
            <div key={i} className="w-3 rounded-sm bg-border" style={{ height: `${h}%` }} />
          ))}
        </div>
      </div>
    )
  }

  // Result card
  return (
    <div className="rounded-lg border border-border bg-bg-surface p-5 flex flex-col gap-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <StatusBadge
          variant={result.is_attack ? 'critical' : 'authorized'}
          label={result.attack_type}
        />
        <RiskBadge level={result.risk_level} />
      </div>

      <div>
        <span className="font-display text-3xl tracking-tight text-text-primary">
          {(result.confidence * 100).toFixed(1)}%
        </span>
        <p className="font-ui text-xs text-text-secondary mt-0.5">CONFIDENCE SCORE</p>
      </div>

      <ConfidenceBar value={result.confidence} size="md" label="Prediction confidence" />

      {result.top_features.length > 0 && (
        <div>
          <p className="mb-2 font-ui text-xs font-semibold tracking-wider text-text-secondary uppercase">
            Top Features
          </p>
          <div className="flex flex-col gap-2">
            {result.top_features.map(f => (
              <div key={f.feature} className="flex items-center gap-2">
                <span className="w-36 font-mono text-xs text-text-secondary truncate">{f.feature}</span>
                <div className="flex-1 h-1.5 rounded-full bg-border overflow-hidden">
                  <div
                    className="h-full rounded-full bg-cyan transition-all"
                    style={{ width: `${Math.round(f.weight * 100)}%` }}
                  />
                </div>
                <span className="font-mono text-xs text-text-tertiary w-8 text-right">
                  {Math.round(f.weight * 100)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
