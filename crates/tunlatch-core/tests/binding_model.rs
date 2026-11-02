//! Pure consistency checks with synthetic platform facts, never real OS authentication.

use tunlatch_core::binding::{
    BindingError, BindingInvalidation, CandidateSnapshot, ControlSocketObservation,
    CorrelatedBinding, InterfaceObservation, MAX_TUN_CANDIDATES, ObservationWindow, OwnershipMatch,
    OwnershipMethod, OwnershipSample, ProcessObservation, ProxyCore, ProxySelection,
    ReportCompleteness, SnapshotCompleteness, SnapshotStamp, UntrustedOwnershipReport,
    VerifiedCurrentBinding,
};
use tunlatch_core::status::{InterfaceAddress, NetworkInterface};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    snapshot: CandidateSnapshot,
    selection: ProxySelection,
    process: ProcessObservation,
    report: UntrustedOwnershipReport,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let stamp = SnapshotStamp {
        observer_epoch: [1; 16],
        generation: 4,
    };
    let interface = InterfaceObservation {
        observation_id: 7,
        interface: NetworkInterface {
            name: "utun4".into(),
            index: 19,
            up: true,
            loopback: false,
            addresses: vec![InterfaceAddress {
                address: "fe80::1".parse()?,
                scope_id: 19,
            }],
        },
    };
    let snapshot = CandidateSnapshot::new(
        stamp,
        10,
        SnapshotCompleteness::Complete,
        vec![interface.clone()],
    )?;
    let process = ProcessObservation {
        pid: 420,
        birth_seconds: 1_800_000_000,
        birth_microseconds: 123,
        uid: 0,
        core: ProxyCore::SingBox,
        loaded_image_sha256: [9; 32],
    };
    let sample = OwnershipSample {
        snapshot: stamp,
        process: process.clone(),
        interface,
        socket: ControlSocketObservation {
            fd: 12,
            method: OwnershipMethod::KernelControlInspection,
            controller_name: "com.apple.net.utun_control".into(),
            controller_id: 4,
            control_unit: 5,
            opaque_socket: 500,
            opaque_pcb: 600,
            associated_interface_name: "utun4".into(),
        },
    };
    let report = UntrustedOwnershipReport {
        collection_sequence: 1,
        completeness: ReportCompleteness::Complete,
        window: ObservationWindow {
            started_at: 9,
            finished_at: 12,
            valid_until: 20,
        },
        matches: vec![OwnershipMatch {
            before: sample.clone(),
            after: sample,
        }],
    };
    Ok(Fixture {
        snapshot,
        selection: ProxySelection::new(ProxyCore::SingBox, [9; 32])?,
        process,
        report,
    })
}

fn correlate(fixture: &Fixture) -> Result<CorrelatedBinding, BindingError> {
    CorrelatedBinding::verify_report(
        &fixture.snapshot,
        &fixture.selection,
        fixture.report.clone(),
        12,
    )
}

fn confirm(fixture: &Fixture) -> Result<VerifiedCurrentBinding, BindingError> {
    let correlation = correlate(fixture)?;
    let intent = correlation.confirmation_intent();
    correlation.confirm(intent, current_correlation(fixture, 2, 12)?, 12)
}

fn current_correlation(
    fixture: &Fixture,
    sequence: u64,
    now: u64,
) -> Result<CorrelatedBinding, BindingError> {
    let mut current = fixture.report.clone();
    current.collection_sequence = sequence;
    current.window.finished_at = now;
    current.window.valid_until = now + 8;
    CorrelatedBinding::verify_report(&fixture.snapshot, &fixture.selection, current, now)
}

fn snapshot_with(
    stamp: SnapshotStamp,
    completeness: SnapshotCompleteness,
    interfaces: Vec<InterfaceObservation>,
) -> Result<CandidateSnapshot, BindingError> {
    CandidateSnapshot::new(stamp, 10, completeness, interfaces)
}

#[test]
fn complete_synthetic_ipv6_only_evidence_can_be_selected_without_pf_authority() -> TestResult {
    let fixture = fixture()?;
    let binding = confirm(&fixture)?;
    assert_eq!(binding.process(), &fixture.process);
    assert_eq!(binding.interface().interface.name, "utun4");
    assert_eq!(binding.interface().interface.addresses.len(), 1);
    let address = &binding.interface().interface.addresses[0];
    assert!(address.address.is_ipv6());
    assert_eq!(address.scope_id, 19);
    let checked = binding
        .revalidate(current_correlation(&fixture, 3, 19)?, 19)
        .map_err(|error| format!("synthetic evidence unexpectedly invalidated: {error:?}"))?;
    let invalidated = checked.invalidate(BindingInvalidation::ObserverInterrupted);
    assert_eq!(
        invalidated.reason(),
        &BindingInvalidation::ObserverInterrupted
    );
    Ok(())
}

#[test]
fn direct_holder_fd_query_is_a_separate_accepted_model_source() -> TestResult {
    let mut fixture = fixture()?;
    fixture.report.matches[0].before.socket.method = OwnershipMethod::HolderFdQuery;
    fixture.report.matches[0].after.socket.method = OwnershipMethod::HolderFdQuery;
    assert!(confirm(&fixture).is_ok());
    Ok(())
}

#[test]
fn names_routes_and_manual_assertions_cannot_substitute_for_direct_evidence() -> TestResult {
    for method in [
        OwnershipMethod::InterfaceNameOnly,
        OwnershipMethod::RouteInference,
        OwnershipMethod::ManualAssertion,
    ] {
        let mut fixture = fixture()?;
        fixture.report.matches[0].before.socket.method = method;
        fixture.report.matches[0].after.socket.method = method;
        assert_eq!(
            correlate(&fixture).err(),
            Some(BindingError::IndirectOwnership)
        );
    }
    Ok(())
}

#[test]
fn unavailable_partial_missing_and_ambiguous_reports_are_rejected() -> TestResult {
    let mut fixture = fixture()?;
    fixture.report.completeness = ReportCompleteness::Unavailable;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::EvidenceUnavailable)
    );
    fixture.report.completeness = ReportCompleteness::Partial;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::PartialEvidence)
    );
    fixture.report.completeness = ReportCompleteness::Complete;
    fixture
        .report
        .matches
        .push(fixture.report.matches[0].clone());
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::AmbiguousOwnership)
    );
    fixture.report.matches.clear();
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::NoOwnershipMatch)
    );
    Ok(())
}

#[test]
fn pid_reuse_during_collection_cannot_preserve_a_process_instance() -> TestResult {
    let mut fixture = fixture()?;
    fixture.report.matches[0].after.process.birth_microseconds += 1;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::ProcessChanged)
    );
    Ok(())
}

#[test]
fn uid_or_core_or_image_change_during_collection_is_rejected() -> TestResult {
    for change in 0..3 {
        let mut fixture = fixture()?;
        let process = &mut fixture.report.matches[0].after.process;
        match change {
            0 => process.uid = 501,
            1 => process.core = ProxyCore::Xray,
            _ => process.loaded_image_sha256 = [8; 32],
        }
        assert_eq!(
            correlate(&fixture).err(),
            Some(BindingError::ProcessChanged)
        );
    }
    Ok(())
}

#[test]
fn unchanged_paths_cannot_authorize_new_core_or_loaded_image_content() -> TestResult {
    for change in 0..2 {
        let mut fixture = fixture()?;
        let pair = &mut fixture.report.matches[0];
        for sample in [&mut pair.before, &mut pair.after] {
            if change == 0 {
                sample.process.core = ProxyCore::Mihomo;
            } else {
                sample.process.loaded_image_sha256 = [8; 32];
            }
        }
        assert_eq!(
            correlate(&fixture).err(),
            Some(BindingError::SoftwareNotSelected)
        );
    }
    Ok(())
}

#[test]
fn malformed_process_facts_do_not_create_correlation() -> TestResult {
    for change in 0..5 {
        let mut fixture = fixture()?;
        let process = &mut fixture.report.matches[0].before.process;
        match change {
            0 => process.pid = 0,
            1 => process.birth_seconds = 0,
            2 => process.birth_microseconds = 1_000_000,
            3 => process.loaded_image_sha256 = [0; 32],
            _ => process.core = ProxyCore::Unknown,
        }
        assert_eq!(
            correlate(&fixture).err(),
            Some(BindingError::InvalidProcessObservation)
        );
    }
    Ok(())
}

#[test]
fn old_epoch_and_generation_are_not_accepted_even_with_matching_names() -> TestResult {
    for epoch_changed in [true, false] {
        let mut fixture = fixture()?;
        let old = &mut fixture.report.matches[0].before.snapshot;
        if epoch_changed {
            old.observer_epoch = [2; 16];
        } else {
            old.generation -= 1;
        }
        assert_eq!(
            correlate(&fixture).err(),
            Some(BindingError::SnapshotChanged)
        );
    }
    Ok(())
}

#[test]
fn same_addresses_and_reused_ifindex_do_not_preserve_interface_instance() -> TestResult {
    let mut fixture = fixture()?;
    fixture.report.matches[0].before.interface.observation_id = 88;
    fixture.report.matches[0].after.interface.observation_id = 88;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::InterfaceChanged)
    );
    Ok(())
}

#[test]
fn interface_name_or_index_change_during_collection_is_rejected() -> TestResult {
    let mut name_change = fixture()?;
    name_change.report.matches[0].after.interface.interface.name = "utun8".into();
    assert_eq!(
        correlate(&name_change).err(),
        Some(BindingError::InterfaceChanged)
    );
    let mut index_change = fixture()?;
    index_change.report.matches[0]
        .after
        .interface
        .interface
        .index = 20;
    index_change.report.matches[0]
        .after
        .interface
        .interface
        .addresses[0]
        .scope_id = 20;
    assert_eq!(
        correlate(&index_change).err(),
        Some(BindingError::InterfaceChanged)
    );
    Ok(())
}

#[test]
fn fd_socket_or_pcb_reuse_during_collection_is_rejected() -> TestResult {
    for change in 0..3 {
        let mut fixture = fixture()?;
        let socket = &mut fixture.report.matches[0].after.socket;
        match change {
            0 => socket.fd += 1,
            1 => socket.opaque_socket += 1,
            _ => socket.opaque_pcb += 1,
        }
        assert_eq!(
            correlate(&fixture).err(),
            Some(BindingError::ControlSocketChanged)
        );
    }
    Ok(())
}

#[test]
fn inconsistent_or_missing_control_metadata_is_rejected() -> TestResult {
    for change in 0..7 {
        let mut fixture = fixture()?;
        let socket = &mut fixture.report.matches[0].before.socket;
        match change {
            0 => socket.controller_name = "com.example.fake_control".into(),
            1 => socket.controller_id = 0,
            2 => socket.control_unit = 6,
            3 => socket.opaque_socket = 0,
            4 => socket.opaque_pcb = 0,
            5 => socket.associated_interface_name = "utun8".into(),
            _ => socket.control_unit = 0,
        }
        assert_eq!(
            correlate(&fixture).err(),
            Some(BindingError::InvalidControlSocket)
        );
    }
    Ok(())
}

#[test]
fn failed_snapshot_continuity_requires_a_rescan() -> TestResult {
    let mut fixture = fixture()?;
    fixture.snapshot = snapshot_with(
        fixture.snapshot.stamp(),
        SnapshotCompleteness::RequiresRescan,
        fixture.snapshot.candidates().to_vec(),
    )?;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::SnapshotIncomplete)
    );
    Ok(())
}

#[test]
fn down_interfaces_remain_candidates_without_obtaining_correlation() -> TestResult {
    let mut fixture = fixture()?;
    let mut interfaces = fixture.snapshot.candidates().to_vec();
    interfaces[0].interface.up = false;
    fixture.snapshot = snapshot_with(
        fixture.snapshot.stamp(),
        SnapshotCompleteness::Complete,
        interfaces.clone(),
    )?;
    fixture.report.matches[0].before.interface = interfaces[0].clone();
    fixture.report.matches[0].after.interface = interfaces[0].clone();
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::InterfaceNotReady)
    );
    Ok(())
}

#[test]
fn collection_times_and_exclusive_evidence_deadline_are_enforced() -> TestResult {
    let mut fixture = fixture()?;
    assert_eq!(
        CorrelatedBinding::verify_report(
            &fixture.snapshot,
            &fixture.selection,
            fixture.report.clone(),
            11
        )
        .err(),
        Some(BindingError::ObservationNotFinished)
    );
    assert_eq!(
        CorrelatedBinding::verify_report(
            &fixture.snapshot,
            &fixture.selection,
            fixture.report.clone(),
            20
        )
        .err(),
        Some(BindingError::EvidenceExpired)
    );
    fixture.report.window.started_at = 13;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::InvalidObservationWindow)
    );
    fixture.report.window.started_at = 11;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::InvalidObservationWindow)
    );
    fixture.report.window.started_at = 9;
    fixture.report.window.valid_until = 12;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::InvalidObservationWindow)
    );
    Ok(())
}

#[test]
fn previous_confirmation_does_not_confirm_new_snapshot_evidence() -> TestResult {
    let old = fixture()?;
    let old_intent = correlate(&old)?.confirmation_intent();
    let mut new = fixture()?;
    let mut stamp = new.snapshot.stamp();
    stamp.generation += 1;
    new.snapshot = snapshot_with(
        stamp,
        SnapshotCompleteness::Complete,
        new.snapshot.candidates().to_vec(),
    )?;
    new.report.matches[0].before.snapshot = stamp;
    new.report.matches[0].after.snapshot = stamp;
    assert_eq!(
        correlate(&new)?
            .confirm(old_intent, current_correlation(&new, 2, 12)?, 12)
            .err(),
        Some(BindingError::ConfirmationMismatch)
    );
    assert!(confirm(&new).is_ok());
    Ok(())
}

#[test]
fn previous_confirmation_cannot_select_another_process_with_the_same_content() -> TestResult {
    let old = fixture()?;
    let intent = correlate(&old)?.confirmation_intent();
    let mut new = fixture()?;
    new.process.pid += 1;
    new.report.matches[0].before.process = new.process.clone();
    new.report.matches[0].after.process = new.process.clone();
    assert_eq!(
        correlate(&new)?
            .confirm(intent, current_correlation(&new, 2, 12)?, 12)
            .err(),
        Some(BindingError::ConfirmationMismatch)
    );
    Ok(())
}

#[test]
fn confirmation_rechecks_current_snapshot_process_and_time() -> TestResult {
    for change in 0..3 {
        let fixture = fixture()?;
        let correlation = correlate(&fixture)?;
        let intent = correlation.confirmation_intent();
        let mut stamp = fixture.snapshot.stamp();
        let mut process = fixture.process.clone();
        let mut now = 12;
        let expected = match change {
            0 => {
                stamp.observer_epoch = [3; 16];
                BindingError::SnapshotChanged
            }
            1 => {
                process.birth_microseconds += 1;
                BindingError::ProcessChanged
            }
            _ => {
                now = 20;
                BindingError::EvidenceExpired
            }
        };
        let current = snapshot_with(
            stamp,
            SnapshotCompleteness::Complete,
            fixture.snapshot.candidates().to_vec(),
        )?;
        let mut report = fixture.report.clone();
        report.matches[0].before.snapshot = stamp;
        report.matches[0].after.snapshot = stamp;
        report.matches[0].before.process = process.clone();
        report.matches[0].after.process = process;
        report.collection_sequence = 2;
        report.window.finished_at = now;
        report.window.valid_until = now + 8;
        let current = CorrelatedBinding::verify_report(&current, &fixture.selection, report, now)?;
        assert_eq!(
            correlation.confirm(intent, current, now).err(),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn revalidation_consumes_stale_binding_and_returns_only_diagnostics() -> TestResult {
    let fixture = fixture()?;
    let binding = confirm(&fixture)?;
    let mut reused = fixture.process.clone();
    reused.birth_seconds += 1;
    let mut report = fixture.report.clone();
    report.collection_sequence = 3;
    report.matches[0].before.process = reused.clone();
    report.matches[0].after.process = reused;
    let current =
        CorrelatedBinding::verify_report(&fixture.snapshot, &fixture.selection, report, 12)?;
    let rejected = binding.revalidate(current, 12).err();
    let invalidated = rejected.ok_or("reused PID was accepted")?;
    assert_eq!(
        invalidated.reason(),
        &BindingInvalidation::CurrentCheckFailed(BindingError::ProcessChanged)
    );
    assert_eq!(invalidated.previous_stamp(), fixture.snapshot.stamp());
    assert_eq!(invalidated.observation_id(), 7);
    let expired = confirm(&fixture)?
        .revalidate(current_correlation(&fixture, 3, 20)?, 20)
        .err()
        .ok_or("expired evidence was accepted")?;
    assert_eq!(
        expired.reason(),
        &BindingInvalidation::CurrentCheckFailed(BindingError::EvidenceExpired)
    );
    Ok(())
}

#[test]
fn confirmation_rejects_current_fd_socket_or_pcb_change_in_the_same_process() -> TestResult {
    for change in 0..3 {
        let mut fixture = fixture()?;
        let prior = correlate(&fixture)?;
        let intent = prior.confirmation_intent();
        let pair = &mut fixture.report.matches[0];
        for sample in [&mut pair.before, &mut pair.after] {
            match change {
                0 => sample.socket.fd += 1,
                1 => sample.socket.opaque_socket += 1,
                _ => sample.socket.opaque_pcb += 1,
            }
        }
        let current = current_correlation(&fixture, 2, 13)?;
        assert_eq!(
            prior.confirm(intent, current, 13).err(),
            Some(BindingError::ControlSocketChanged)
        );
    }
    Ok(())
}

#[test]
fn revalidation_requires_current_direct_ownership_and_rejects_reopened_fds() -> TestResult {
    for change in 0..3 {
        let mut fixture = fixture()?;
        let binding = confirm(&fixture)?;
        let pair = &mut fixture.report.matches[0];
        for sample in [&mut pair.before, &mut pair.after] {
            match change {
                0 => sample.socket.fd += 1,
                1 => sample.socket.opaque_socket += 1,
                _ => sample.socket.opaque_pcb += 1,
            }
        }
        let current = current_correlation(&fixture, 3, 13)?;
        let invalidated = binding
            .revalidate(current, 13)
            .err()
            .ok_or("changed direct ownership was accepted")?;
        assert_eq!(
            invalidated.reason(),
            &BindingInvalidation::CurrentCheckFailed(BindingError::ControlSocketChanged)
        );
    }
    Ok(())
}

#[test]
fn current_collection_cannot_regress_after_a_successful_direct_refresh() -> TestResult {
    let fixture = fixture()?;
    let refreshed = confirm(&fixture)?
        .revalidate(current_correlation(&fixture, 3, 19)?, 19)
        .map_err(|error| format!("fresh synthetic report rejected: {error:?}"))?;
    let invalidated = refreshed
        .revalidate(current_correlation(&fixture, 4, 18)?, 20)
        .err()
        .ok_or("older collection replaced newer evidence")?;
    assert_eq!(
        invalidated.reason(),
        &BindingInvalidation::CurrentCheckFailed(BindingError::ObservationRegressed)
    );
    Ok(())
}

#[test]
fn confirmation_rejects_an_exact_replay_despite_a_second_model_verification() -> TestResult {
    let fixture = fixture()?;
    let prior = correlate(&fixture)?;
    let intent = prior.confirmation_intent();
    // Raw data can be cloned and rechecked. Only the collector counter distinguishes this
    // replay from a new collection; non-Clone CorrelatedBinding is not sufficient by itself.
    let replay = correlate(&fixture)?;
    assert_eq!(
        prior.confirm(intent, replay, 12).err(),
        Some(BindingError::CollectionSequenceNotAdvanced)
    );
    Ok(())
}

#[test]
fn revalidation_rejects_the_complete_previous_report_even_while_it_is_unexpired() -> TestResult {
    let fixture = fixture()?;
    let binding = confirm(&fixture)?;
    let mut previous = fixture.report.clone();
    previous.collection_sequence = 2;
    let replay =
        CorrelatedBinding::verify_report(&fixture.snapshot, &fixture.selection, previous, 13)?;
    let invalidated = binding
        .revalidate(replay, 13)
        .err()
        .ok_or("complete old report was accepted as a new collection")?;
    assert_eq!(
        invalidated.reason(),
        &BindingInvalidation::CurrentCheckFailed(BindingError::CollectionSequenceNotAdvanced)
    );
    Ok(())
}

#[test]
fn extending_a_replayed_deadline_does_not_create_fresh_confirmation_or_refresh() -> TestResult {
    for confirming in [true, false] {
        let fixture = fixture()?;
        let mut extended = fixture.report.clone();
        extended.collection_sequence = if confirming { 1 } else { 2 };
        extended.window.valid_until = 1_000;
        let current =
            CorrelatedBinding::verify_report(&fixture.snapshot, &fixture.selection, extended, 13)?;
        if confirming {
            let prior = correlate(&fixture)?;
            let intent = prior.confirmation_intent();
            assert_eq!(
                prior.confirm(intent, current, 13).err(),
                Some(BindingError::CollectionSequenceNotAdvanced)
            );
        } else {
            let invalidated = confirm(&fixture)?
                .revalidate(current, 13)
                .err()
                .ok_or("deadline extension replay was accepted")?;
            assert_eq!(
                invalidated.reason(),
                &BindingInvalidation::CurrentCheckFailed(
                    BindingError::CollectionSequenceNotAdvanced
                )
            );
        }
    }
    Ok(())
}

#[test]
fn new_collections_with_a_coarse_equal_timestamp_are_accepted_only_with_new_sequences() -> TestResult
{
    let fixture = fixture()?;
    let binding = confirm(&fixture)?;
    assert_eq!(binding.collection_sequence(), 2);
    let refreshed = binding
        .revalidate(current_correlation(&fixture, 3, 12)?, 12)
        .map_err(|error| format!("new coarse-clock collection rejected: {error:?}"))?;
    assert_eq!(refreshed.collection_sequence(), 3);
    Ok(())
}

#[test]
fn an_advanced_sequence_does_not_allow_the_collection_start_to_regress() -> TestResult {
    let fixture = fixture()?;
    let mut report = fixture.report.clone();
    report.collection_sequence = 3;
    report.window.started_at = 8;
    report.window.finished_at = 13;
    let current =
        CorrelatedBinding::verify_report(&fixture.snapshot, &fixture.selection, report, 13)?;
    let invalidated = confirm(&fixture)?
        .revalidate(current, 13)
        .err()
        .ok_or("regressed collection start was accepted")?;
    assert_eq!(
        invalidated.reason(),
        &BindingInvalidation::CurrentCheckFailed(BindingError::ObservationRegressed)
    );
    Ok(())
}

#[test]
fn a_zero_collection_sequence_cannot_produce_correlation() -> TestResult {
    let mut fixture = fixture()?;
    fixture.report.collection_sequence = 0;
    assert_eq!(
        correlate(&fixture).err(),
        Some(BindingError::InvalidCollectionSequence)
    );
    Ok(())
}

#[test]
fn lost_ownership_or_core_change_requires_new_collection_and_confirmation() -> TestResult {
    for reason in [
        BindingInvalidation::OwnershipEvidenceLost,
        BindingInvalidation::CoreOrContentChanged,
        BindingInvalidation::ReconfirmationRequired,
    ] {
        let fixture = fixture()?;
        let invalidated = confirm(&fixture)?.invalidate(reason.clone());
        assert_eq!(invalidated.reason(), &reason);
        assert!(
            confirm(&fixture).is_ok(),
            "new synthetic evidence can be confirmed anew"
        );
    }
    Ok(())
}

#[test]
fn multiple_tuns_do_not_implicitly_share_one_ownership_match() -> TestResult {
    let mut fixture = fixture()?;
    let mut interfaces = fixture.snapshot.candidates().to_vec();
    let mut other = interfaces[0].clone();
    other.observation_id += 1;
    other.interface.name = "utun9".into();
    other.interface.index = 24;
    other.interface.addresses[0].scope_id = 24;
    interfaces.push(other);
    fixture.snapshot = snapshot_with(
        fixture.snapshot.stamp(),
        SnapshotCompleteness::Complete,
        interfaces,
    )?;
    let binding = confirm(&fixture)?;
    assert_eq!(binding.interface().interface.name, "utun4");
    assert_eq!(fixture.snapshot.candidates().len(), 2);
    Ok(())
}

#[test]
fn snapshot_rejects_duplicate_ids_names_and_indices() -> TestResult {
    for change in 0..3 {
        let fixture = fixture()?;
        let mut interfaces = fixture.snapshot.candidates().to_vec();
        let mut duplicate = interfaces[0].clone();
        duplicate.observation_id += 1;
        duplicate.interface.name = "utun8".into();
        duplicate.interface.index = 23;
        duplicate.interface.addresses[0].scope_id = 23;
        match change {
            0 => duplicate.observation_id = interfaces[0].observation_id,
            1 => duplicate
                .interface
                .name
                .clone_from(&interfaces[0].interface.name),
            _ => {
                duplicate.interface.index = interfaces[0].interface.index;
                duplicate.interface.addresses[0].scope_id = interfaces[0].interface.index;
            }
        }
        interfaces.push(duplicate);
        assert_eq!(
            snapshot_with(
                fixture.snapshot.stamp(),
                SnapshotCompleteness::Complete,
                interfaces
            )
            .err(),
            Some(BindingError::DuplicateCandidate)
        );
    }
    Ok(())
}

#[test]
fn oversized_snapshots_are_rejected_before_resolving_candidate_ambiguity() -> TestResult {
    let fixture = fixture()?;
    let repeated = fixture.snapshot.candidates()[0].clone();
    assert_eq!(
        snapshot_with(
            fixture.snapshot.stamp(),
            SnapshotCompleteness::Complete,
            vec![repeated; MAX_TUN_CANDIDATES + 1],
        )
        .err(),
        Some(BindingError::TooManyCandidates)
    );
    Ok(())
}

#[test]
fn ipv4_only_and_dual_stack_addresses_are_preserved_without_becoming_identity() -> TestResult {
    for dual_stack in [false, true] {
        let mut fixture = fixture()?;
        let mut interface = fixture.snapshot.candidates()[0].clone();
        if !dual_stack {
            interface.interface.addresses.clear();
        }
        interface.interface.addresses.push(InterfaceAddress {
            address: "192.0.2.9".parse()?,
            scope_id: 0,
        });
        fixture.snapshot = snapshot_with(
            fixture.snapshot.stamp(),
            SnapshotCompleteness::Complete,
            vec![interface.clone()],
        )?;
        fixture.report.matches[0].before.interface = interface.clone();
        fixture.report.matches[0].after.interface = interface;
        let binding = confirm(&fixture)?;
        assert_eq!(
            binding.interface().interface.addresses.len(),
            if dual_stack { 2 } else { 1 }
        );
        assert!(
            binding
                .interface()
                .interface
                .addresses
                .iter()
                .any(|address| address.address.is_ipv4() && address.scope_id == 0)
        );
    }
    Ok(())
}

#[test]
fn invalid_scope_loopback_name_or_zero_instance_metadata_is_rejected() -> TestResult {
    for change in 0..7 {
        let fixture = fixture()?;
        let mut interfaces = fixture.snapshot.candidates().to_vec();
        let interface = &mut interfaces[0];
        match change {
            0 => interface.interface.addresses[0].scope_id = 0,
            1 => interface.interface.loopback = true,
            2 => interface.interface.name = "en0".into(),
            3 => interface.interface.index = 0,
            4 => interface.observation_id = 0,
            5 => interface.interface.name = "utun1234567890123".into(),
            _ => interface.interface.addresses[0].address = "192.0.2.1".parse()?,
        }
        assert_eq!(
            snapshot_with(
                fixture.snapshot.stamp(),
                SnapshotCompleteness::Complete,
                interfaces
            )
            .err(),
            Some(BindingError::InvalidCandidate)
        );
    }
    Ok(())
}

#[test]
fn zero_epoch_generation_or_unknown_software_cannot_be_selected() -> TestResult {
    for stamp in [
        SnapshotStamp {
            observer_epoch: [0; 16],
            generation: 1,
        },
        SnapshotStamp {
            observer_epoch: [1; 16],
            generation: 0,
        },
    ] {
        assert_eq!(
            snapshot_with(stamp, SnapshotCompleteness::Complete, vec![]).err(),
            Some(BindingError::InvalidSnapshotStamp)
        );
    }
    assert_eq!(
        ProxySelection::new(ProxyCore::Unknown, [9; 32]).err(),
        Some(BindingError::InvalidSoftwareSelection)
    );
    assert_eq!(
        ProxySelection::new(ProxyCore::SingBox, [0; 32]).err(),
        Some(BindingError::InvalidSoftwareSelection)
    );
    Ok(())
}

#[test]
fn report_json_is_only_untrusted_data_and_rejects_forged_trust_fields() -> TestResult {
    let fixture = fixture()?;
    let encoded = serde_json::to_string(&fixture.report)?;
    let raw: UntrustedOwnershipReport = serde_json::from_str(&encoded)?;
    assert_eq!(raw, fixture.report);
    let mut forged = serde_json::to_value(&fixture.report)?;
    forged["verified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<UntrustedOwnershipReport>(forged).is_err());
    let mut forged = serde_json::to_value(&fixture.report)?;
    forged["matches"][0]["before"]["process"]["path"] = serde_json::json!("/trusted/name");
    assert!(serde_json::from_value::<UntrustedOwnershipReport>(forged).is_err());
    let mut missing = serde_json::to_value(&fixture.report)?;
    missing["matches"][0]["after"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<UntrustedOwnershipReport>(missing).is_err());
    Ok(())
}

#[test]
fn untrusted_json_with_changed_birth_identity_still_fails_model_checks() -> TestResult {
    let fixture = fixture()?;
    let mut value = serde_json::to_value(&fixture.report)?;
    value["matches"][0]["after"]["process"]["birth_seconds"] = serde_json::json!(2_000_000_000_u64);
    let report: UntrustedOwnershipReport = serde_json::from_value(value)?;
    assert_eq!(
        CorrelatedBinding::verify_report(&fixture.snapshot, &fixture.selection, report, 12).err(),
        Some(BindingError::ProcessChanged)
    );
    Ok(())
}
