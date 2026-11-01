import type { Evidence } from "../api/client";

// Archives, folders and AD1 images: one volume made from the archive listing.
const COLLECTION_TYPES = new Set(["raw_collection", "velociraptor_zip", "kape_archive", "parsed_folder", "linux_triage", "macos_triage"]);

export function isBrowsableCollection(evidence: Pick<Evidence, "evidence_type"> | null | undefined): boolean {
  return COLLECTION_TYPES.has(String(evidence?.evidence_type ?? ""));
}

/** Evidence whose files the disk file explorer can show: a disk image or a collection. */
export function isBrowsableEvidence(evidence: Pick<Evidence, "evidence_type" | "disk_image"> | null | undefined): boolean {
  return Boolean(evidence?.disk_image) || isBrowsableCollection(evidence);
}

export function browsableKind(evidence: Pick<Evidence, "evidence_type" | "disk_image" | "original_filename">): string {
  if (evidence.disk_image) return `Disk image · ${String(evidence.disk_image.format || "").toUpperCase() || "image"}`;
  if (/\.ad1$/i.test(evidence.original_filename)) return "AD1 logical image";
  return "Collection";
}
