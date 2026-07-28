use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_skbx-route")
}

#[test]
fn describe_bootstraps_an_agent() {
    let output = Command::new(binary())
        .arg("describe")
        .output()
        .expect("run skbx-route describe");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("describe JSON");
    assert_eq!(value["contract_version"], "routeq/0.1.0");
    assert_eq!(value["limits"]["max_packets"], 256);
    assert_eq!(
        value["platform"]["live_trace"],
        "Linux IPv4 with IP_RECVERR"
    );
}

#[test]
fn plan_is_read_only_and_fully_bounded() {
    let output = Command::new(binary())
        .args([
            "plan",
            "does-not-need-to-resolve.invalid",
            "--max-hops",
            "8",
            "--probes",
            "3",
            "--json",
        ])
        .output()
        .expect("run skbx-route plan");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    assert_eq!(value["target"], "does-not-need-to-resolve.invalid");
    assert_eq!(value["max_packets"], 24);
    assert_eq!(value["flow_strategy"], "fixed_five_tuple");
    assert_eq!(value["active_enrichment"], false);
}

#[test]
fn demo_replay_and_explain_are_machine_stable() {
    let first = Command::new(binary())
        .arg("demo")
        .output()
        .expect("first demo");
    let second = Command::new(binary())
        .arg("demo")
        .output()
        .expect("second demo");
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());

    let file = NamedTempFile::new().expect("temporary routeq file");
    fs::write(file.path(), &first.stdout).expect("write demo routeq");
    let replay = Command::new(binary())
        .args(["replay", file.path().to_str().unwrap(), "--format", "json"])
        .output()
        .expect("replay demo");
    assert!(replay.status.success());
    let summary: Value = serde_json::from_slice(&replay.stdout).expect("summary JSON");
    assert_eq!(summary["hops"], 4);
    assert_eq!(summary["responsive_hops"], 3);
    assert_eq!(summary["destination_reached"], true);
    assert_eq!(summary["complete"], true);

    let hop: Value = serde_json::from_slice(
        first
            .stdout
            .split(|byte| *byte == b'\n')
            .nth(1)
            .expect("second JSONL record"),
    )
    .expect("hop JSON");
    let handle = hop["hop"]["handle"].as_str().expect("hop handle");
    let explanation = Command::new(binary())
        .args(["explain", file.path().to_str().unwrap(), handle])
        .output()
        .expect("explain demo hop");
    assert!(explanation.status.success());
    let value: Value = serde_json::from_slice(&explanation.stdout).expect("explanation JSON");
    assert_eq!(value["hop"]["ttl"], 1);
    assert_eq!(value["hop"]["dossier"]["claims"][0]["level"], "observed");
}
