# Browser

## What the app supports

The platform supports two paths for browser evidence:

1. CSV/JSON already parsed by BrowserHistoryView, KAPE, NirSoft, or other compatible tools.
2. Direct parsing from Velociraptor collections for:
   - Chromium `History`
   - Firefox `places.sqlite`

## Prioritized artifacts

- History
- Downloads
- Search terms

Not processed at this stage:

- Cookies
- Passwords
- Autofill
- Other sensitive browser data

## Supported or inferred browsers

- Chrome
- Edge
- Brave
- Chromium
- Opera
- Firefox
- IE/Edge Legacy only if already parsed in CSV/JSON

## Extracted fields

- `browser.name`
- `browser.profile`
- `browser.url`
- `browser.domain`
- `browser.title`
- `browser.search_terms`
- `download.target_path`
- `download.file_name`
- `download.total_bytes`
- `url.full`
- `file.path`

## Direct parsing from Velociraptor

For Chromium, selective extraction and safe copy of `History` is used, along with `History-wal` and `History-shm` when they exist. The app does not need to extract the entire Velociraptor collection to reach those SQLite files.

Main tables:

- `urls`
- `visits`
- `downloads`
- `downloads_url_chains`
- `keyword_search_terms`

For Firefox, selective extraction and safe copy of `places.sqlite` is used, along with `places.sqlite-wal` and `places.sqlite-shm` when they exist.

Main tables:

- `moz_places`
- `moz_historyvisits`

Firefox downloads can vary by version and are not always extracted as clearly as in Chromium.

Browser artifacts not extracted by default in this flow:

- `Cache`
- `Code Cache`
- `GPUCache`
- `Service Worker`
- `IndexedDB`
- `Local Storage`
- `Cookies`
- `Login Data`
- `Web Data`

## Correlation

The app correlates browser downloads with:

- MFT/USN for file creation
- LNK and Jump Lists for opening
- Prefetch and EVTX for execution
- Defender for subsequent detections

## Limitations

- At this stage, parsed outputs and raw history/places SQLite are prioritized.
- Hindsight, XLSX, or third-party JSON can still be useful, but are not always the best source for automating the platform.
- History does not imply download.
- Download does not imply execution.
- Firefox downloads may not appear depending on version/profile/base.

## Common false positives

- Legitimate downloads of administrative tools
- Visits to cloud services with no malicious activity
- Technical or troubleshooting searches
