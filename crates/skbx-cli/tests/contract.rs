use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_skbx")
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.traceq.jsonl")
}

#[test]
fn describe_bootstraps_an_agent() {
    let output = Command::new(binary())
        .args(["describe", "--format", "json"])
        .output()
        .expect("run skbx describe");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("describe JSON");
    assert_eq!(value["contract_version"], "traceq/0.1.0");
    assert_eq!(value["defaults"]["max_events"], 100_000);
}

#[test]
fn replay_and_explain_are_machine_stable() {
    let input = fixture();
    let first = Command::new(binary())
        .args(["replay", input.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("first replay");
    let second = Command::new(binary())
        .args(["replay", input.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("second replay");
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);

    let summary: Value = serde_json::from_slice(&first.stdout).expect("summary JSON");
    assert_eq!(summary["events"], 3);
    assert_eq!(summary["distinct_skbs"], 2);
    assert_eq!(summary["functions"]["ip_rcv"], 2);

    let explanation = Command::new(binary())
        .args([
            "explain",
            input.to_str().unwrap(),
            "event:000000000000000000000000",
        ])
        .output()
        .expect("explain");
    assert!(explanation.status.success());
    let evidence: Value = serde_json::from_slice(&explanation.stdout).expect("explanation JSON");
    assert_eq!(evidence["target"]["function"]["symbol"], "ip_rcv");
    assert_eq!(evidence["same_skb_evidence"].as_array().unwrap().len(), 2);
}
