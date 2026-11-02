# Policy fixture provenance

`policy-contract.json` is a tracked copy of the frozen `policy-v2/2` configuration and digest vectors. Its metadata identifies the source bytes; tests never read ignored local documentation.

The 68 configuration and one canonical-byte/digest vectors are W13 input-model checks. The source also has 29 full-boundary decision, five state transition, four application-authorization and five envelope vectors. Those 43 vectors require later enforcement/state/IPC work and are deliberately not counted as passing W13 tests. Ordinary selector and conditional-egress properties are checked separately in `policy_model.rs`; no live grant, trusted egress or PF result is created.

The additional two configuration vectors verify hard resource rejection before diagnostics for simultaneous invalid version/oversized arrays and deeply nested unknown data. Schema, normalized bytes and egress semantics remain unchanged.
