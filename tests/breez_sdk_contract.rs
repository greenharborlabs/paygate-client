#![cfg(feature = "breez-qualification")]

//! Offline compile contract for the pinned Breez Spark API.  This test never
//! constructs an SDK, connects, or polls the network; its async body is only
//! type-checked by rustc.

use breez_sdk_spark::{
    BreezSdk, GetInfoRequest, PaymentRequest, PrepareSendPaymentRequest,
    PrepareSendPaymentResponse, SendPaymentOptions, SendPaymentRequest,
};

async fn bolt11_only_contract(sdk: &BreezSdk, prepared: PrepareSendPaymentResponse) {
    let info = sdk.get_info(GetInfoRequest {
        ensure_synced: Some(false),
    });
    let prepared = match sdk
        .prepare_send_payment(PrepareSendPaymentRequest {
            payment_request: PaymentRequest::Input {
                input: "lnbc1offlinecontract".to_owned(),
            },
            amount: None,
            token_identifier: None,
            conversion_options: None,
            fee_policy: None,
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(_) => return,
    };
    let sent = sdk.send_payment(SendPaymentRequest {
        prepare_response: prepared,
        options: Some(SendPaymentOptions::Bolt11Invoice {
            prefer_spark: false,
            completion_timeout_secs: Some(1),
        }),
        idempotency_key: None,
    });
    let disconnected = sdk.disconnect();

    // Keep response fields in the pinned contract: these are the only output
    // values a production seam may use to derive proof material.
    if let Ok(response) = sent.await {
        let _ = (
            response.payment.amount,
            response.payment.fees,
            response.payment.details,
        );
    }
    let _ = (info.await, disconnected.await);
}

#[test]
fn pinned_breez_bolt11_api_type_checks_without_network() {
    let _ = bolt11_only_contract;
}
