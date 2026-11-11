# Importing evidence from Azure Blob Storage

Kairon can import one blob from an Azure Storage account as evidence, the same way it imports an object from S3 (see [s3-import.md](s3-import.md)). The server downloads the blob and then processes it exactly like a file uploaded from the browser: same SHA-256, same preflight inspection, same registration and ingest. Nothing about the resulting evidence depends on where it came from, apart from the upload session's record of the account, container, blob, ETag and version.

Any blob type can be imported: block blobs (archives, collections, memory images), append blobs and page blobs — a VM disk exported from Azure is a page blob VHD, which then goes through the normal disk image handling. It is not a live mount of the container: the whole blob is copied to the server first.

## Turning it on

Downloading from Azure reaches outside the lab, so the feature is off by default.

1. Set `AZURE_BLOB_SOURCE_ENABLED=true` in the server's `.env` and restart the backend and worker (`docker compose up -d backend worker`).
2. As an administrator, open **Azure Blob Source** in the sidebar and enter:
   - **Account URL**: `https://<account>.blob.core.windows.net`, or the endpoint of a sovereign cloud (`*.blob.core.usgovcloudapi.net`, `*.blob.core.chinacloudapi.cn`) or of the Azurite emulator (`http://<host>:10000/<account>`).
   - **Authentication**, one of:
     - **SAS token** (recommended for a one-off engagement): an account or container shared access signature with **read** and **list** permissions (`sp=rl`) and an expiry. Paste it with or without the leading `?`.
     - **Service principal (Entra ID)**: the tenant ID, the application's client ID and a client secret. Give the application the **Storage Blob Data Reader** role on the account or the evidence container.
     - **Account key**: one of the account's access keys. It grants full control of the account; prefer one of the above. The account name is taken from the URL unless given.
   - Optionally a **Default container** the wizard opens on.

   The key, SAS or client secret is encrypted at rest with a key derived from `KAIRON_AI_SECRET_KEY` (or `KAIRON_SESSION_SECRET` when that is unset), separate from the ones protecting the S3 secret and AI provider keys, and is never sent back to the browser. Rotating that secret makes the stored one unreadable; enter it again. Switching the authentication method discards the stored secret of the previous method.
3. **Test connection** checks the values in the form, saved or not, by listing the container (all a container SAS needs to allow).

## Importing a blob

In the evidence wizard, open **Advanced import options** and tick **Import from Azure Blob container** (shown only when the feature is on and configured). Pick a container from the list of those the credential can see (an account key, an account SAS with the *service* resource type, or a role on the account can list them; with a container SAS or a container-scoped role, type the container name instead). Browse the container folder by folder (virtual folders, or real directories on an account with hierarchical namespace / Data Lake Storage Gen2), select one blob and choose **Inspect evidence**. The wizard shows the download's progress, then the usual preflight report; from there the flow is the normal one.

- The exact blob that was picked is downloaded: its version when the account keeps blob versions, otherwise a download that fails if the blob's ETag changed in the meantime.
- Blobs in the **Archive** tier cannot be imported until they are rehydrated to Hot or Cool in Azure (a pending rehydration still counts as archived).
- The blob must fit the server's upload size limit and free space, like any upload. A page blob's size is its provisioned size, empty pages included.
- Closing the wizard does not stop the download: it continues on the server as an upload session of the case, and cancelling that session stops it.
- A failed download marks the upload session as failed with the reason (access denied, SAS expired, blob changed, account unreachable...); import it again to retry. Unlike a browser upload, it cannot be resumed from the wizard.

Every configuration change and every import start is recorded in the audit log (account, container, blob, size and the upload session).
