# Python oracle transition boundary

The frozen `f56cbd0` Python process is evidence only for behavior it exposes
through its public CLI, payer, and synchronous policy interfaces.  In
particular, it does not expose a pre-submission/post-submission marker or a
typed cancellation result.  An interruption escaping `PolicyApproval.execute`
is therefore recorded as an ambiguous historical interruption, not re-labelled
as a wallet-submission fact.

Rust `BeforeSubmission` rollback and `AfterSubmissionUnknown` retention are
intentional security deltas, owned by W2-02 adapter/integration tests.  They
have no Python-oracle observation pointer and cannot be accepted by synthetic
reserve, commit, or rollback operations in the historical probe.
