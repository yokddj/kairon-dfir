# WMI

## What the app supports

The app currently supports:

- parsed CSV of `__EventFilter`
- parsed CSV of `CommandLineEventConsumer`
- parsed CSV of `ActiveScriptEventConsumer`
- parsed CSV of `__FilterToConsumerBinding`
- equivalent parsed JSON
- Autoruns/Sysinternals CSV when it contains WMI entries
- classification of `Microsoft-Windows-WMI-Activity/Operational` events already parsed by EVTX
- raw discovery of the WMI repository:
  - `OBJECTS.DATA`
  - `INDEX.BTR`
  - `MAPPING*.MAP`

## What is parsed directly from Velociraptor

It is parsed directly from a Velociraptor collection when the collection already contains:

- parsed WMI CSV/JSON
- WMI Activity EVTX that then goes through the EVTX parser

The raw WMI repository under `C:\Windows\System32\wbem\Repository\` is detected and preserved, but in this iteration it remains `detected_not_implemented`.

## What Filter, Consumer, and Binding are

- `__EventFilter`: defines the WQL condition that triggers something.
- `EventConsumer`: defines what to do when the filter is met.
- `__FilterToConsumerBinding`: joins filter and consumer.

Useful WMI persistence usually requires the full chain:

1. filter
2. consumer
3. binding

## Important consumers

### CommandLineEventConsumer

This is especially relevant because it can execute:

- `powershell`
- `cmd.exe`
- `wscript`
- `cscript`
- `mshta`
- `rundll32`
- `regsvr32`

### ActiveScriptEventConsumer

This is relevant because it can contain `VBScript` or `JScript` embedded in `ScriptText`.

## How to interpret WMI Activity vs WMI Persistence

- `WMI Activity EVTX` can indicate queries, errors, or activity in the WMI subsystem.
- `WMI Activity EVTX` alone does not prove persistence.
- `WMI persistence candidate` requires at least a reasonable correlation between filter, consumer, and binding.

## Main fields

The app extracts and normalizes, when available:

- `wmi.namespace`
- `wmi.class_name`
- `wmi.name`
- `wmi.filter_name`
- `wmi.consumer_name`
- `wmi.query`
- `wmi.query_language`
- `wmi.command_line_template`
- `wmi.executable_path`
- `wmi.script_text`
- `wmi.script_preview`
- `wmi.binding_filter`
- `wmi.binding_consumer`
- `wmi.creator_sid`
- `wmi.creator_user`
- WMI timestamps

## What increases risk

- `CommandLineEventConsumer` with `powershell -enc`
- `ActiveScriptEventConsumer` with a non-empty script
- WQL query with:
  - `Win32_ProcessStartTrace`
  - `RegistryValueChangeEvent`
  - `__InstanceCreationEvent`
  - `__InstanceModificationEvent`
  - `__TimerEvent`
- complete `binding` between filter and consumer
- URLs, downloads, or paths in `AppData`, `Temp`, `ProgramData`, `Public`
- subsequent correlation with Defender, Prefetch, Amcache, or MFT

## Correlations the app makes

- WMI -> PowerShell
- WMI -> Defender
- WMI -> Prefetch / execution
- WMI -> Amcache / ShimCache
- WMI -> MFT / USN
- WMI -> Browser / BITS
- WMI -> Scheduled Tasks

## Common false positives

- management agents
- legitimate WMI-based monitoring
- corporate software using benign consumers
- WMI Activity EVTX with errors or administrative queries without real persistence

## Current limitations

- raw `OBJECTS.DATA` still has no real binary parser
- `WMI Activity EVTX` does not always prove persistence
- a `consumer` or `binding` alone does not prove real execution

## Investigation examples

- search `artifact.type = wmi` and filter by `wmi.consumer_name`, `wmi.query`, or `wmi.command_line_template`
- check whether the following exist:
  - filter
  - consumer
  - binding
- pivot the `executable_path` or the URL toward:
  - Defender
  - Prefetch
  - PowerShell
  - MFT
  - BITS
