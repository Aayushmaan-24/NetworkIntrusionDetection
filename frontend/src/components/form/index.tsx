import { type ReactNode, type InputHTMLAttributes, type SelectHTMLAttributes } from 'react'
import { type UseFormRegisterReturn, type FieldError } from 'react-hook-form'
import { cn } from '@/lib/utils'

// ── Shared label + error wrapper ─────────────────────────────
function FieldWrapper({
  label, htmlFor, required, error, helpText, children,
}: {
  label:     string
  htmlFor:   string
  required?: boolean
  error?:    FieldError
  helpText?: string
  children:  ReactNode
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label
        htmlFor={htmlFor}
        className="font-ui text-xs font-semibold tracking-wider text-text-secondary uppercase"
      >
        {label}
        {required && <span className="ml-1 text-critical" aria-hidden="true">*</span>}
      </label>
      {children}
      {helpText && !error && (
        <p className="font-ui text-xs text-text-tertiary">{helpText}</p>
      )}
      {error && (
        <p
          id={`${htmlFor}-error`}
          role="alert"
          className="font-ui text-xs text-critical"
        >
          {error.message}
        </p>
      )}
    </div>
  )
}

const inputBase = (error?: FieldError) => cn(
  'h-9 w-full rounded-md border bg-bg-input px-3 font-mono text-base text-text-primary',
  'placeholder:text-text-tertiary placeholder:font-mono',
  'transition-colors duration-150',
  'focus:outline-none focus:shadow-focus focus:border-cyan',
  'disabled:cursor-not-allowed disabled:opacity-40',
  error
    ? 'border-critical focus:shadow-[0_0_0_1px_#FF3B3B]'
    : 'border-border hover:border-border-strong'
)

// ── FormInput ─────────────────────────────────────────────────
interface FormInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'id'> {
  label:     string
  name:      string
  register?: UseFormRegisterReturn
  error?:    FieldError
  helpText?: string
  unit?:     string
}

export function FormInput({ label, name, register, error, helpText, unit, required, className, ...rest }: FormInputProps) {
  return (
    <FieldWrapper label={label} htmlFor={name} required={required} error={error} helpText={helpText}>
      <div className="relative">
        <input
          id={name}
          aria-required={required}
          aria-invalid={!!error}
          aria-describedby={error ? `${name}-error` : undefined}
          className={cn(inputBase(error), unit && 'pr-16', className)}
          {...register}
          {...rest}
        />
        {unit && (
          <span className="absolute right-3 top-1/2 -translate-y-1/2 font-mono text-xs text-text-tertiary">
            {unit}
          </span>
        )}
      </div>
    </FieldWrapper>
  )
}

// ── FormSelect ────────────────────────────────────────────────
interface FormSelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'id'> {
  label:    string
  name:     string
  options:  string[]
  register?: UseFormRegisterReturn
  error?:   FieldError
  loading?: boolean
  helpText?: string
}

export function FormSelect({ label, name, options, register, error, loading, required, helpText, className, ...rest }: FormSelectProps) {
  return (
    <FieldWrapper label={label} htmlFor={name} required={required} error={error} helpText={helpText}>
      <div className="relative">
        <select
          id={name}
          aria-required={required}
          aria-invalid={!!error}
          aria-describedby={error ? `${name}-error` : undefined}
          aria-busy={loading}
          disabled={loading || rest.disabled}
          className={cn(
            inputBase(error),
            'appearance-none cursor-pointer',
            'text-text-primary',
            loading && 'opacity-50 cursor-wait',
            className
          )}
          {...register}
          {...rest}
        >
          <option value="" className="bg-bg-elevated text-text-tertiary">
            {loading ? 'Loading...' : '— Select —'}
          </option>
          {options.map(opt => (
            <option key={opt} value={opt} className="bg-bg-elevated text-text-primary">
              {opt}
            </option>
          ))}
        </select>

        {/* Chevron icon */}
        <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-muted">
          {loading ? (
            <svg className="animate-spin h-3.5 w-3.5" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
          ) : (
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </span>
      </div>
    </FieldWrapper>
  )
}

// ── FormToggle ────────────────────────────────────────────────
interface FormToggleProps {
  label:    string
  name:     string
  checked:  boolean
  onChange: (val: boolean) => void
  helpText?: string
}

export function FormToggle({ label, name, checked, onChange, helpText }: FormToggleProps) {
  return (
    <div className="flex flex-col gap-1.5">
      <label
        htmlFor={name}
        className="font-ui text-xs font-semibold tracking-wider text-text-secondary uppercase"
      >
        {label}
      </label>
      <div className="flex items-center gap-3">
        <button
          id={name}
          type="button"
          role="switch"
          aria-checked={checked}
          onClick={() => onChange(!checked)}
          className={cn(
            'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border border-transparent',
            'transition-colors duration-200 focus:outline-none focus-visible:shadow-focus',
            checked ? 'bg-cyan' : 'bg-border-strong'
          )}
        >
          <span
            className={cn(
              'pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow',
              'transform transition-transform duration-200',
              checked ? 'translate-x-4' : 'translate-x-0.5'
            )}
          />
        </button>
        <span className={cn('font-mono text-xs', checked ? 'text-cyan' : 'text-text-tertiary')}>
          {checked ? 'TRUE' : 'FALSE'}
        </span>
      </div>
      {helpText && <p className="font-ui text-xs text-text-tertiary">{helpText}</p>}
    </div>
  )
}

// ── FieldGroup ────────────────────────────────────────────────
interface FieldGroupProps {
  title:    string
  icon?:    ReactNode
  children: ReactNode
  className?: string
}

export function FieldGroup({ title, icon, children, className }: FieldGroupProps) {
  return (
    <section
      aria-labelledby={`group-${title.replace(/\s+/g, '-').toLowerCase()}`}
      className={cn('rounded-lg border border-border bg-bg-surface p-5', className)}
    >
      <div className="mb-4 flex items-center gap-2 border-b border-border pb-3">
        {icon && <span className="text-cyan">{icon}</span>}
        <h2
          id={`group-${title.replace(/\s+/g, '-').toLowerCase()}`}
          className="font-display text-xs tracking-wider text-cyan uppercase"
        >
          {title}
        </h2>
      </div>
      {children}
    </section>
  )
}
