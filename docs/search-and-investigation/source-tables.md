# Source Tables

Source Tables is a Timeline Explorer style view for CSV and TSV files: one file,
all of its columns, sortable and filterable by any of them.

## Why it exists

Normal ingestion turns each CSV row into a normalized event with a strict
mapping, and keeps the original row in `raw` without indexing it. That is what
Search, Timeline and detections need, but it means a column the normalizer does
not know cannot be sorted or filtered. Source Tables indexes the file a second
time, whole, with every column it brings.

## How to create a table

Tables are opt-in:

- **Evidence wizard**: tick *Full CSV tables* to build a table for every CSV/TSV
  of the upload.
- **Evidence detail**: build a table for one file.
- **Source Tables page** (sidebar): lists every CSV/TSV of the case that has no
  table yet, grouped by evidence, with **Full table** (one file) and **Full table
  for all** (every file of one evidence).

## What the view offers

- Sort by any column.
- Filters per column: contains, does not contain, is, is not, empty, not empty.
- The most frequent values of a column.
- Hide columns; columns with no value in the whole file are flagged (*empty*)
  and can be hidden in one click.
- Row detail and export of the filtered rows to CSV.

## How it is stored

- Each table has its own OpenSearch index, `dfir-tables-<case>-<table>`; the
  ordered header list is kept in PostgreSQL.
- Columns are stored by position (`c0`, `c1`…), so headers with dots, spaces,
  duplicates or no name never reach the mapping.
- Values longer than 8,191 characters are kept and exported but not indexed, so
  they cannot be sorted or matched by an exact or contains filter.
- Search, Timeline, Find Evil and detections query the events indices only and
  never read these tables, so nothing appears twice.
- Deleting a table removes its index; the evidence and its events are untouched.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/cases/{case_id}/source-tables` | Tables of the case and CSV/TSV files without a table. |
| `POST /api/cases/{case_id}/evidence/{evidence_id}/source-tables` | Build tables for one file or every file of an evidence. |
| `GET /api/cases/{case_id}/source-tables/{table_id}` | Table metadata and columns. |
| `POST /api/cases/{case_id}/source-tables/{table_id}/rows` | Rows with sort and filters. |
| `POST /api/cases/{case_id}/source-tables/{table_id}/values` | Most frequent values of a column. |
| `POST /api/cases/{case_id}/source-tables/{table_id}/export` | Filtered rows as CSV. |
| `DELETE /api/cases/{case_id}/source-tables/{table_id}` | Delete a table. |

Code: `backend/app/services/source_tables.py`,
`backend/app/api/routes_source_tables.py`,
`frontend/src/pages/SourceTablesPage.tsx`.
