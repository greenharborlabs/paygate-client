use paygate::payers::base::{
    AttemptExitClass, LedgerAction, PaymentAttemptOutcome, PaymentError, PostSubmitCondition,
    RawPaymentResult,
};

fn raw() -> RawPaymentResult {
    RawPaymentResult {
        amount_sats: 21,
        fee_sats: 1,
        payment_hash: Some("00".repeat(32)),
        preimage_hex: Some("11".repeat(32)),
    }
}

#[test]
fn exact_attempt_truth_table_is_monotonic_after_submission() {
    let cases = [
        (
            PaymentAttemptOutcome::NotSubmitted(PaymentError::FeeExceeded),
            false,
            LedgerAction::Release,
            false,
            true,
            AttemptExitClass::RuntimeFailure,
        ),
        (
            PaymentAttemptOutcome::SubmittedFailedFinal(PaymentError::Transport),
            false,
            LedgerAction::Release,
            false,
            false,
            AttemptExitClass::RuntimeFailure,
        ),
        (
            PaymentAttemptOutcome::SubmittedUnknown(PaymentError::Timeout),
            false,
            LedgerAction::Commit,
            false,
            false,
            AttemptExitClass::RuntimeFailure,
        ),
        (
            PaymentAttemptOutcome::Confirmed {
                raw: raw(),
                post_submit_conditions: vec![],
            },
            true,
            LedgerAction::Commit,
            true,
            false,
            AttemptExitClass::Success,
        ),
    ];

    for (outcome, paid, ledger, authorize, retry, exit) in cases {
        assert_eq!(outcome.is_paid(), paid);
        assert_eq!(outcome.ledger_action(), ledger);
        assert_eq!(outcome.authorization_eligible(), authorize);
        assert_eq!(outcome.retry_is_safe(), retry);
        assert_eq!(outcome.exit_class(), exit);
    }
}

#[test]
fn confirmed_conditions_accumulate_without_losing_proof_or_counting_state() {
    let outcome = PaymentAttemptOutcome::Confirmed {
        raw: raw(),
        post_submit_conditions: vec![
            PostSubmitCondition::FinalFeeExceeded,
            PostSubmitCondition::DisconnectFailed,
        ],
    };

    assert!(outcome.is_paid());
    assert_eq!(outcome.ledger_action(), LedgerAction::Commit);
    assert!(outcome.authorization_eligible());
    assert!(!outcome.retry_is_safe());
    assert_eq!(outcome.exit_class(), AttemptExitClass::RuntimeFailure);
    assert_eq!(
        outcome.post_submit_conditions(),
        &[
            PostSubmitCondition::FinalFeeExceeded,
            PostSubmitCondition::DisconnectFailed,
        ]
    );
    assert_eq!(outcome.confirmed_raw().unwrap().amount_sats, 21);
    assert_eq!(outcome.primary_error(), Some(&PaymentError::Transport));
}

#[test]
fn confirmed_primary_error_is_cleanup_first_then_fee() {
    for (conditions, expected) in [
        (vec![], None),
        (
            vec![PostSubmitCondition::FinalFeeExceeded],
            Some(&PaymentError::FeeExceeded),
        ),
        (
            vec![PostSubmitCondition::DisconnectFailed],
            Some(&PaymentError::Transport),
        ),
        (
            vec![
                PostSubmitCondition::FinalFeeExceeded,
                PostSubmitCondition::DisconnectFailed,
            ],
            Some(&PaymentError::Transport),
        ),
    ] {
        let outcome = PaymentAttemptOutcome::Confirmed {
            raw: raw(),
            post_submit_conditions: conditions,
        };
        assert_eq!(outcome.primary_error(), expected);
        assert!(outcome.is_paid());
        assert_eq!(outcome.ledger_action(), LedgerAction::Commit);
        assert!(outcome.authorization_eligible());
    }
}
