# Bounded TDX quote generation

The three-host CDS pilot reproduced secret-read EOFs during a burst of twelve
concurrent attestations. The destination CDS logged five-second TLS handshake
timeouts while the caller's local attester was generating ConfigFS quotes at
approximately one-second intervals. Quote generation performed blocking hardware
I/O directly on Tokio workers, delaying the verification needed by the handshake.

TDX generation now has one dedicated hardware thread, reached through a bounded
message queue. One request executes and at most sixteen wait. Each queued request
holds its own 64-byte REPORTDATA, quote-method choice, and one-shot reply. A full
queue returns `QuoteQueueFull`, exposed by the API as HTTP 503 with error code
`quote_queue_full`. There is no automatic request retry or evidence reuse.

Canceled queued requests are skipped. Cancellation of an executing request does
not release its execution slot before the hardware call finishes. A stopped
worker fails closed. This applies to bare-metal TDX and the GCP TDX path that
calls the same generator. The existing hardware methods, evidence validation,
collateral verification, and CDS timeouts are unchanged.

Local tests use a blocked hardware substitute on a single-thread async runtime
to check scheduling, overflow, cancellation, request/result binding, and error
propagation. The API test checks that overload is reported as unavailable rather
than a verification verdict. Native hardware qualification remains separate;
these tests alone establish no burst capacity or availability guarantee.

This pilot branch starts from the exact `c52cd8e` attester version in the CDS
images so the next comparison can isolate the scheduling change.
