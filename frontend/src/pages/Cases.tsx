import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import CaseCard from "../components/CaseCard";
import { useActiveCase } from "../context/ActiveCaseContext";

export default function Cases() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { activeCaseId, clearActiveCase } = useActiveCase();
  const { data, isLoading, error } = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const mutation = useMutation({
    mutationFn: () => api.createCase({ name, description, status: "open" }),
    onSuccess: (createdCase) => {
      setName("");
      setDescription("");
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      void navigate(`/cases/${createdCase.id}/overview`);
    },
  });
  const deleteMutation = useMutation({
    mutationFn: (caseId: string) => api.deleteCase(caseId),
    onSuccess: async (_, deletedCaseId) => {
      if (activeCaseId === deletedCaseId) {
        clearActiveCase();
      }
      await queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  return (
    <div className="space-y-8">
      <section className="grid gap-6 lg:grid-cols-[1.1fr_1.9fr]">
        <div className="rounded-3xl border border-line bg-panel/70 p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Create case</p>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="ACME Incident 001"
            className="mt-4 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
          />
          <textarea
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="Short description of the investigation scope"
            className="mt-3 h-32 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50"
          />
          {mutation.error ? <p className="mt-3 text-sm text-danger">{mutation.error.message}</p> : null}
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || !name.trim()}
            className="mt-4 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-50"
          >
            {mutation.isPending ? "Creating..." : "Create Case"}
          </button>
          <p className="mt-3 text-xs text-muted">Al crear el caso entrarás directamente a su vista de detalle para subir evidencias. También puedes borrar casos desde cada tarjeta.</p>
        </div>
        <div>
          {isLoading ? <p className="text-sm text-muted">Loading cases...</p> : null}
          {error instanceof Error ? <p className="text-sm text-danger">{error.message}</p> : null}
          {deleteMutation.error instanceof Error ? <p className="mb-3 text-sm text-danger">{deleteMutation.error.message}</p> : null}
          <div className="grid gap-4 md:grid-cols-2">
            {(data ?? []).map((item) => (
              <CaseCard
                key={item.id}
                item={item}
                onDelete={(selected) => {
                  if (deleteMutation.isPending) return;
                  if (!window.confirm(`Delete case "${selected.name}" and all its evidences, artifacts and indexed events? This action cannot be undone.`)) return;
                  deleteMutation.mutate(selected.id);
                }}
              />
            ))}
          </div>
          {!isLoading && !error && !data?.length ? (
            <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">
              No cases yet. Create the first case on the left and the interface will take you straight to evidence upload.
            </div>
          ) : null}
        </div>
      </section>
    </div>
  );
}
