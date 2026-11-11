import { api, type AzureBlobEntry } from "../api/client";
import { CloudObjectPicker } from "./CloudObjectPicker";

// Browses the instance's Azure Blob source one virtual folder at a time and lets the analyst pick one blob.
export function AzureBlobPicker({
  caseId,
  accountName,
  defaultContainer,
  selected,
  onSelect,
}: {
  caseId: string;
  accountName: string;
  defaultContainer: string;
  selected: { container: string; object: AzureBlobEntry } | null;
  onSelect: (value: { container: string; object: AzureBlobEntry } | null) => void;
}) {
  return (
    <CloudObjectPicker<AzureBlobEntry>
      testIdPrefix="azure-blob"
      containerLabel="Container"
      containerPlaceholder="container name"
      defaultContainer={defaultContainer}
      queryKey={`azure-blobs-${caseId}`}
      list={(container, prefix, token) => api.listAzureBlobs(caseId, { container: container || undefined, prefix, token: token ?? undefined })}
      listContainers={() => api.listAzureBlobContainers(caseId)}
      location={(container, key) => `${accountName ? `${accountName}/` : ""}${container}/${key}`}
      isArchived={(item) => item.archived}
      archivedTitle="Archive tier: rehydrate the blob in Azure before importing"
      selected={selected}
      onSelect={onSelect}
    />
  );
}
