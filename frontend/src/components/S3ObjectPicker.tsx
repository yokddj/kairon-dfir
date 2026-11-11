import { api, type S3ObjectEntry } from "../api/client";
import { CloudObjectPicker } from "./CloudObjectPicker";

const ARCHIVED = new Set(["GLACIER", "DEEP_ARCHIVE"]);

// Browses the instance's S3 source one "folder" (prefix) at a time and lets the analyst pick one object.
export function S3ObjectPicker({
  caseId,
  defaultBucket,
  selected,
  onSelect,
}: {
  caseId: string;
  defaultBucket: string;
  selected: { bucket: string; object: S3ObjectEntry } | null;
  onSelect: (value: { bucket: string; object: S3ObjectEntry } | null) => void;
}) {
  return (
    <CloudObjectPicker<S3ObjectEntry>
      testIdPrefix="s3"
      containerLabel="Bucket"
      containerPlaceholder="bucket name"
      defaultContainer={defaultBucket}
      queryKey={`s3-objects-${caseId}`}
      list={(bucket, prefix, token) => api.listS3Objects(caseId, { bucket: bucket || undefined, prefix, token: token ?? undefined })}
      location={(bucket, key) => `s3://${bucket}/${key}`}
      isArchived={(item) => ARCHIVED.has(item.storage_class ?? "")}
      archivedTitle="Archived (Glacier): restore it in S3 before importing"
      selected={selected ? { container: selected.bucket, object: selected.object } : null}
      onSelect={(value) => onSelect(value ? { bucket: value.container, object: value.object } : null)}
    />
  );
}
