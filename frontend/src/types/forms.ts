import { z } from 'zod'

// ── Rate field (0.0 – 1.0) ───────────────────────────────────
const rateField = (label: string) =>
  z.number({
    required_error: `${label} is required`,
    invalid_type_error: `${label} must be a number`,
  })
    .min(0, `${label} must be ≥ 0.0`)
    .max(1, `${label} must be ≤ 1.0`)

// ── Integer count field with configurable max ────────────────
const countField = (max: number, label: string) =>
  z.number({
    required_error: `${label} is required`,
    invalid_type_error: `${label} must be a whole number`,
  })
    .int(`${label} must be a whole number`)
    .min(0, `${label} must be ≥ 0`)
    .max(max, `${label} must be ≤ ${max}`)

// ── Main schema ──────────────────────────────────────────────
export const PredictFormSchema = z.object({
  // Group A — Network Metadata
  duration:       z.number({ required_error: 'Duration is required' }).int().min(0, 'Must be ≥ 0'),
  protocol_type:  z.string().min(1, 'Select a protocol'),
  service:        z.string().min(1, 'Select a service'),
  flag:           z.string().min(1, 'Select a flag'),
  src_bytes:      z.number({ required_error: 'Source bytes is required' }).int().min(0),
  dst_bytes:      z.number({ required_error: 'Destination bytes is required' }).int().min(0),
  land:           z.boolean(),

  // Group B — Session State
  logged_in:      z.boolean(),
  count:          countField(511, 'Count'),
  srv_count:      countField(511, 'SRV count'),
  serror_rate:    rateField('SYN error rate'),
  rerror_rate:    rateField('REJ error rate'),
  same_srv_rate:  rateField('Same service rate'),

  // Group C — Host-Based Features
  dst_host_count:           countField(255, 'Dst host count'),
  dst_host_srv_count:       countField(255, 'Dst host SRV count'),
  dst_host_same_srv_rate:   rateField('Dst host same srv rate'),
  dst_host_diff_srv_rate:   rateField('Dst host diff srv rate'),
  dst_host_serror_rate:     rateField('Dst host SYN error rate'),
})

export type PredictFormValues = z.infer<typeof PredictFormSchema>

// ── Default form values ──────────────────────────────────────
export const PREDICT_FORM_DEFAULTS: PredictFormValues = {
  duration:                 0,
  protocol_type:            '',
  service:                  '',
  flag:                     '',
  src_bytes:                0,
  dst_bytes:                0,
  land:                     false,
  logged_in:                false,
  count:                    0,
  srv_count:                0,
  serror_rate:              0,
  rerror_rate:              0,
  same_srv_rate:            0,
  dst_host_count:           0,
  dst_host_srv_count:       0,
  dst_host_same_srv_rate:   0,
  dst_host_diff_srv_rate:   0,
  dst_host_serror_rate:     0,
}
