# Importing evidence from S3

Kairon can import one object from an S3 bucket (AWS S3 or an S3-compatible store such as MinIO, Ceph or Wasabi) as evidence. The server downloads the object and then processes it exactly like a file uploaded from the browser: same SHA-256, same preflight inspection, same registration and ingest. Nothing about the resulting evidence depends on where it came from, apart from the upload session's record of the bucket, key, ETag and version.

It is not a live mount of the bucket: the whole object is copied to the server first.

## Turning it on

Downloading from S3 reaches outside the lab, so the feature is off by default.

1. Set `S3_SOURCE_ENABLED=true` in the server's `.env` and restart the backend and worker (`docker compose up -d backend worker`).
2. As an administrator, open **S3 Source** in the sidebar and enter:
   - **Access key ID** and **Secret access key**. The secret is encrypted at rest with a key derived from `KAIRON_AI_SECRET_KEY` (or `KAIRON_SESSION_SECRET` when that is unset), separate from the one protecting AI provider keys, and is never sent back to the browser. Rotating that secret makes the stored S3 secret unreadable; enter it again.
   - **Region** and, optionally, a **Default bucket** the wizard opens on.
   - **Endpoint URL** only for an S3-compatible store (for example `https://minio.example:9000`), with **Path-style addressing** when the store needs it (most MinIO and Ceph setups).
3. **Test connection** checks the values in the form, saved or not.

Use a key that can only read the evidence bucket: `s3:ListBucket` on the bucket and `s3:GetObject` on its objects (plus `s3:GetObjectVersion` when the bucket is versioned).

## Importing an object

In the evidence wizard, open **Advanced import options** and tick **Import from S3 bucket** (shown only when the feature is on and configured). Pick a bucket from the list of those the key can see (it needs `s3:ListAllMyBuckets`; otherwise type the bucket name). Browse the bucket folder by folder, select one object and choose **Inspect evidence**. The wizard shows the download's progress, then the usual preflight report; from there the flow is the normal one.

- The exact object that was picked is downloaded: its version ID when the bucket is versioned, otherwise a download that fails if the object's ETag changed in the meantime.
- Objects in Glacier or Deep Archive cannot be imported until they are restored in S3.
- The object must fit the server's upload size limit and free space, like any upload.
- Closing the wizard does not stop the download: it continues on the server as an upload session of the case, and cancelling that session stops it.
- A failed download marks the upload session as failed with the reason (access denied, object changed, endpoint unreachable...); import it again to retry. Unlike a browser upload, it cannot be resumed from the wizard.

Every configuration change and every import start is recorded in the audit log (bucket, key, size and the upload session).
