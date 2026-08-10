// Reusable "Completed with warning" banner (Phase 2). Shown when the most
// recent plugin run for this evidence completed with 0 rows AND
// Volatility's own stderr reported it could not stack VMware snapshot
// metadata (backend: app.services.memory.execution.
// VMWARE_METADATA_WARNING_CODE, surfaced via Memory Preparation's
// zero_result_warning_* fields -- see that endpoint's docstring for why
// it does not ride the family-results endpoints).
//
// Deliberately NOT a failure state: the plugin run's own status stays
// "completed" on the backend. This banner never claims otherwise.
//
// Mounted alongside VmwareCompanionSection (both wizard and persistent
// evidence page); its CTA scrolls to that section rather than opening a
// second, separate upload flow.

type Props = {
  warningCode: string | null;
  warningMessage: string | null;
  pluginName: string | null;
  onOpenCompanionSection: () => void;
};

export function ZeroResultWarningBanner({ warningCode, warningMessage, pluginName, onOpenCompanionSection }: Props) {
  if (!warningCode) return null;

  return (
    <div
      className="mt-4 rounded-2xl border border-amber/30 bg-amber/10 p-4"
      data-testid="zero-result-warning-banner"
      role="status"
    >
      <p className="text-sm font-semibold text-amber">Completed with warning</p>
      <p className="mt-1 text-sm text-ink">
        0 results recovered{pluginName ? <> from <span className="font-mono text-xs">{pluginName}</span></> : null}.
      </p>
      <p className="mt-1 text-xs text-muted">{warningMessage ?? "Volatility reported that VMware snapshot metadata may be required."}</p>
      <button
        type="button"
        onClick={onOpenCompanionSection}
        className="mt-3 rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss"
        data-testid="zero-result-warning-cta"
      >
        Add VMware metadata
      </button>
    </div>
  );
}
