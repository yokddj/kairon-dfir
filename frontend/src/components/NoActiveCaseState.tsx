import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";

const DEMO_CASE_NAME = "Demo - ACME Incident 001";

type NoActiveCaseStateProps = {
  title?: string;
  description?: string;
};

export default function NoActiveCaseState({
  title = "No active case selected",
  description = "Select or create a case first to open this investigation workspace.",
}: NoActiveCaseStateProps) {
  const demoCaseQuery = useQuery({
    queryKey: ["cases", "demo-shortcut"],
    queryFn: api.listCases,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });

  const demoCase =
    demoCaseQuery.data?.find((item) => item.name === DEMO_CASE_NAME) ??
    demoCaseQuery.data?.find((item) => item.name.toLowerCase().startsWith("demo - "));

  return (
    <section className="rounded-[28px] border border-line bg-panel/70 p-8 shadow-panel">
      <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Case workspace</p>
      <h2 className="mt-2 text-2xl font-semibold">{title}</h2>
      <p className="mt-3 max-w-2xl text-sm text-muted">{description}</p>
      <div className="mt-6 flex flex-wrap gap-3">
        <Link to="/cases" className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss">
          Select case
        </Link>
        <Link to="/cases" className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">
          Create case
        </Link>
        {demoCase ? (
          <Link to={`/cases/${demoCase.id}/overview`} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">
            Open demo case
          </Link>
        ) : null}
      </div>
    </section>
  );
}
