
"""CyberSentry AI — Integrated Application Dashboard."""

from datetime import datetime, timezone
from io import BytesIO

import pandas as pd
import streamlit as st

from core.ingestion import validate_and_parse_file
from core.evidence_integrity import (
    create_evidence_manifest,
    verify_evidence_integrity,
)
from core.normalization import normalize_logs
from core.detection_rules import run_detection_rules
from core.anomaly_model import detect_anomalies
from core.correlation import correlate_events
from core.timeline import build_timeline, summarize_timeline

from database.db import (
    initialize_database,
    create_case,
    list_cases,
    add_evidence,
    add_finding,
    update_case_status,
    add_audit_entry,
    get_case_details,
    create_incident_record,
    list_incident_records,
    update_incident_record,
)

from reports.pdf_generator import generate_investigation_pdf


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="CyberSentry AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

initialize_database()


def initialize_session_state():
    """Initialize application session variables."""
    defaults = {
        "intake_results": {},
        "intake_errors": {},
        "analysis_cache": {},
        "saved_analysis": set(),
        "generated_reports": {},
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_session_state()


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def safe_int(value, default=0):
    """Convert a value to an integer without propagating NaN."""
    try:
        if value is None or pd.isna(value):
            return default
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def get_case_options():
    """Retrieve investigation cases from the database."""
    try:
        return list_cases()
    except Exception as exc:
        st.error(f"Could not load investigation cases: {exc}")
        return []


def get_incident_options():
    """Retrieve persistent incident records."""
    try:
        return list_incident_records()
    except Exception as exc:
        st.error(f"Could not load incidents: {exc}")
        return []


def render_dataframe(dataframe, max_rows=500):
    """Display a dataframe with a bounded preview."""
    if dataframe is None:
        st.info("No data available.")
        return

    if not isinstance(dataframe, pd.DataFrame):
        dataframe = pd.DataFrame(dataframe)

    if dataframe.empty:
        st.info("No records available.")
        return

    st.dataframe(
        dataframe.head(max_rows),
        use_container_width=True,
        hide_index=True,
    )

    if len(dataframe) > max_rows:
        st.caption(
            f"Showing {max_rows:,} of {len(dataframe):,} records."
        )


def analyze_evidence(dataframe):
    """Run the log-analysis pipeline on a validated dataframe."""
    normalized = normalize_logs(dataframe)
    anomalies = detect_anomalies(normalized)
    correlated = correlate_events(anomalies)
    timeline = build_timeline(correlated)
    findings = run_detection_rules(normalized)

    if (
        "is_anomaly" in anomalies.columns
        and not anomalies.empty
    ):
        anomaly_mask = (
            anomalies["is_anomaly"]
            .fillna(False)
            .astype(bool)
        )
        anomaly_findings = anomalies.loc[anomaly_mask].copy()
    else:
        anomaly_findings = anomalies.iloc[0:0].copy()

    timeline_summary = summarize_timeline(timeline)

    return {
        "normalized": normalized,
        "anomalies": anomalies,
        "correlated": correlated,
        "timeline": timeline,
        "findings": findings,
        "anomaly_findings": anomaly_findings,
        "timeline_summary": timeline_summary,
    }


def save_analysis_to_database(case_id, filename, result, analysis):
    """Register evidence and persist rule and anomaly findings."""
    manifest = result["manifest"]

    add_evidence(
        case_id=case_id,
        filename=filename,
        sha256=manifest["sha256"],
        file_size=result["file_size"],
        evidence_status="HASHED",
    )

    saved_count = 0

    # Save rule-based findings.
    findings = analysis["findings"]

    if isinstance(findings, pd.DataFrame):
        for _, row in findings.iterrows():
            finding = row.to_dict()

            add_finding(
                case_id=case_id,
                rule_id=str(finding.get("rule_id", "UNKNOWN")),
                title=str(finding.get("title", "Untitled finding")),
                severity=str(finding.get("severity", "MEDIUM")),
                category=str(finding.get("category", "GENERAL")),
                description=str(finding.get("description", "")),
                source_ip=str(finding.get("source_ip", "") or ""),
                username=str(finding.get("username", "") or ""),
                event_count=safe_int(finding.get("event_count", 0)),
            )
            saved_count += 1

    # Save ML anomalies as investigative leads.
    anomaly_rows = analysis["anomaly_findings"]

    if isinstance(anomaly_rows, pd.DataFrame):
        for _, row in anomaly_rows.iterrows():
            anomaly = row.to_dict()
            score = anomaly.get("anomaly_score", "N/A")

            add_finding(
                case_id=case_id,
                rule_id="ML-ANOMALY",
                title="ML anomaly flagged",
                severity="MEDIUM",
                category="Anomaly Detection",
                description=(
                    "The anomaly model flagged an unusual event. "
                    f"Score: {score}. Analyst review is required."
                ),
                source_ip=str(anomaly.get("source_ip", "") or ""),
                username=str(anomaly.get("username", "") or ""),
                event_count=1,
            )
            saved_count += 1

    add_audit_entry(
        case_id=case_id,
        action="ANALYSIS_SAVED",
        actor="analyst",
        details=(
            f"Registered evidence file {filename}; "
            f"saved {saved_count} finding(s)."
        ),
    )

    return saved_count


def get_case_timeline(case_details):
    """Build a combined timeline from cached analyses for case evidence."""
    evidence_records = case_details.get("evidence", [])
    filenames = {
        str(record.get("filename", ""))
        for record in evidence_records
    }

    timeline_frames = []

    for filename in filenames:
        if not filename:
            continue

        analysis = st.session_state.analysis_cache.get(filename)

        if not isinstance(analysis, dict):
            continue

        timeline_df = analysis.get("timeline")

        if isinstance(timeline_df, pd.DataFrame) and not timeline_df.empty:
            timeline_frames.append(timeline_df.copy())

    if not timeline_frames:
        return pd.DataFrame()

    combined = pd.concat(timeline_frames, ignore_index=True)

    if "timeline_time_utc" in combined.columns:
        combined = combined.sort_values(
            "timeline_time_utc",
            na_position="last",
        ).reset_index(drop=True)

    return combined


def get_case_report(case_id):
    """Create and cache a PDF report for an investigation case."""
    details = get_case_details(case_id)

    if not details:
        raise ValueError("The selected investigation case was not found.")

    timeline = get_case_timeline(details)

    pdf_bytes = generate_investigation_pdf(
        case_details=details,
        evidence=details.get("evidence", []),
        findings=details.get("findings", []),
        timeline=timeline,
        audit_entries=details.get("audit_entries", []),
    )

    st.session_state.generated_reports[case_id] = {
        "bytes": pdf_bytes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    return pdf_bytes


# =========================================================
# HEADER AND NAVIGATION
# =========================================================

st.sidebar.title("🛡️ CyberSentry AI")
st.sidebar.caption("Digital Forensics & Incident Response")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Evidence & Analysis",
        "Investigation Cases",
        "Incident Response",
        "Reports & Audit",
    ],
)

st.sidebar.divider()
st.sidebar.caption("Local investigation prototype")

st.title("🛡️ CyberSentry AI")
st.subheader("AI-Assisted Digital Forensics & Incident Response")

st.write(
    "A unified workspace for evidence intake, integrity verification, "
    "security detection, event correlation, incident tracking, "
    "and investigation reporting."
)


# =========================================================
# 1. OVERVIEW
# =========================================================

if page == "Overview":
    cases = get_case_options()

    total_evidence = 0
    active_cases = 0
    open_findings = 0

    for case in cases:
        if case.get("status") != "CLOSED":
            active_cases += 1

        details = get_case_details(case["id"])

        if details:
            total_evidence += len(details.get("evidence", []))
            open_findings += sum(
                1
                for finding in details.get("findings", [])
                if finding.get("status") not in {"CLOSED", "RESOLVED"}
            )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Investigation Cases", len(cases))
    col2.metric("Active Cases", active_cases)
    col3.metric("Registered Evidence", total_evidence)
    col4.metric("Open Findings", open_findings)

    st.divider()
    st.header("Platform Capabilities")

    modules = [
        (
            "Evidence Intake",
            "CSV and JSON validation with file and row limits.",
        ),
        (
            "Evidence Integrity",
            "SHA-256 fingerprints and verification checks.",
        ),
        (
            "Log Normalization",
            "Standardized event fields and timestamps.",
        ),
        (
            "Rule-Based Detection",
            "Configured security indicators and detection rules.",
        ),
        (
            "ML Anomaly Detection",
            "Isolation Forest-based identification of unusual events.",
        ),
        (
            "Event Correlation",
            "Groups potentially related events for investigation.",
        ),
        (
            "Forensic Timeline",
            "Chronological event review using normalized timestamps.",
        ),
        (
            "Case Management",
            "Persistent cases, evidence, findings, and audit entries.",
        ),
        (
            "Incident Response",
            "Incident status tracking and documented response actions.",
        ),
        (
            "PDF Reports",
            "Downloadable investigation and evidence summaries.",
        ),
    ]

    for start in range(0, len(modules), 2):
        left, right = st.columns(2)

        for column, item in zip(
            (left, right),
            modules[start:start + 2],
        ):
            with column:
                with st.container(border=True):
                    st.markdown(f"**{item[0]}**")
                    st.caption(item[1])

    st.divider()

    st.info(
        "Recommended workflow: create a case, upload authorized log files, "
        "review analysis results, register the evidence, track incidents, "
        "and generate an investigation report."
    )


# =========================================================
# 2. EVIDENCE & ANALYSIS
# =========================================================

elif page == "Evidence & Analysis":
    st.header("Evidence Intake and Analysis")

    st.write(
        "Upload authorized CSV or JSON logs. Validate the contents and "
        "review analysis results before registering them to a case."
    )

    uploaded_files = st.file_uploader(
        "Upload forensic log files",
        type=["csv", "json"],
        accept_multiple_files=True,
        help=(
            "Maximum 10 files per selection. Each file must also pass "
            "the ingestion module's size and row limits."
        ),
    )

    if uploaded_files:
        if len(uploaded_files) > 10:
            st.error("Please upload no more than 10 files at once.")
        else:
            for uploaded_file in uploaded_files:
                filename = uploaded_file.name
                content = uploaded_file.getvalue()

                result = validate_and_parse_file(filename, content)

                if result.get("valid", False):
                    manifest = create_evidence_manifest(
                        filename,
                        content,
                    )

                    result["manifest"] = manifest
                    result["content"] = content

                    st.session_state.intake_results[filename] = result
                    st.session_state.intake_errors.pop(filename, None)
                else:
                    st.session_state.intake_errors[filename] = (
                        result.get("errors", ["File validation failed."])
                    )
                    st.session_state.intake_results.pop(filename, None)
                    st.session_state.analysis_cache.pop(filename, None)

    for filename, errors in st.session_state.intake_errors.items():
        with st.expander(f"Rejected file: {filename}"):
            for error in errors:
                st.error(str(error))

    cases = get_case_options()

    if not cases:
        st.warning(
            "Create an investigation case in the Investigation Cases "
            "section before registering evidence."
        )
        selected_case = None
    else:
        selected_case = st.selectbox(
            "Investigation case",
            options=cases,
            format_func=lambda case: (
                f"{case['case_number']} — {case['title']}"
            ),
            key="analysis_case_selection",
        )

    if not st.session_state.intake_results:
        st.info("No accepted evidence files are available yet.")

    for filename, result in list(
        st.session_state.intake_results.items()
    ):
        with st.expander(
            f"{filename} — {result.get('row_count', 0):,} records",
            expanded=True,
        ):
            st.success("The file passed initial intake validation.")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Records",
                result.get("row_count", 0),
            )
            col2.metric(
                "File Size",
                f"{result.get('file_size', 0):,} bytes",
            )
            col3.metric(
                "Format",
                str(result.get("format", "unknown")).upper(),
            )

            manifest = result["manifest"]

            st.markdown("#### Evidence Integrity")

            st.write(
                "Algorithm:",
                manifest.get("hash_algorithm", "SHA-256"),
            )
            st.code(str(manifest.get("sha256", "")))
            st.caption(
                f"Recorded (UTC): {manifest.get('created_at_utc', 'N/A')}"
            )

            integrity = verify_evidence_integrity(
                manifest["sha256"],
                result["content"],
            )

            if integrity.get("integrity_verified", False):
                st.success(
                    "The current file bytes match the recorded fingerprint."
                )
            else:
                st.error(
                    "Integrity verification failed. Review the evidence "
                    "before relying on this copy."
                )

            for warning in result.get("warnings", []):
                st.warning(str(warning))

            st.markdown("#### Original Records")
            render_dataframe(result["dataframe"], max_rows=20)

            try:
                analysis = analyze_evidence(result["dataframe"])
                st.session_state.analysis_cache[filename] = analysis

                st.markdown("#### Normalized Logs")
                render_dataframe(
                    analysis["normalized"],
                    max_rows=20,
                )

                st.markdown("#### Rule-Based Findings")
                findings = analysis["findings"]

                if findings.empty:
                    st.info("No configured rule matches were found.")
                else:
                    st.metric("Rule Matches", len(findings))
                    render_dataframe(findings)

                st.markdown("#### ML Anomaly Detection")

                anomalies = analysis["anomaly_findings"]

                if len(result["dataframe"]) < 5:
                    st.warning(
                        "This dataset has fewer than five events. "
                        "Interpret anomaly results cautiously."
                    )

                if anomalies.empty:
                    st.info("No events were flagged by the current model.")
                else:
                    st.warning(
                        f"The model flagged {len(anomalies)} event(s). "
                        "These are investigative leads, not proof "
                        "of malicious activity."
                    )
                    render_dataframe(anomalies)

                st.markdown("#### Event Correlation")

                correlated = analysis["correlated"]

                if (
                    "correlation_status" in correlated.columns
                    and not correlated.empty
                ):
                    correlated_rows = correlated[
                        correlated["correlation_status"] == "CORRELATED"
                    ]
                    st.metric(
                        "Events in Correlated Groups",
                        len(correlated_rows),
                    )

                render_dataframe(correlated, max_rows=100)

                st.markdown("#### Forensic Timeline")

                summary = analysis["timeline_summary"]

                c1, c2, c3 = st.columns(3)

                c1.metric(
                    "Timeline Events",
                    summary.get("total_events", 0),
                )
                c2.metric(
                    "Valid Timestamps",
                    summary.get("timestamped_events", 0),
                )
                c3.metric(
                    "Invalid Timestamps",
                    summary.get("events_without_valid_timestamp", 0),
                )

                st.write(
                    "Start (UTC):",
                    summary.get("start_time_utc") or "N/A",
                )
                st.write(
                    "End (UTC):",
                    summary.get("end_time_utc") or "N/A",
                )

                render_dataframe(
                    analysis["timeline"],
                    max_rows=100,
                )

                if selected_case:
                    save_key = (
                        selected_case["id"],
                        filename,
                        manifest["sha256"],
                    )

                    if save_key in st.session_state.saved_analysis:
                        st.success(
                            "This evidence and its findings have already "
                            "been registered to this case in this session."
                        )
                    elif st.button(
                        "Register Evidence and Save Findings",
                        key=f"save_analysis_{filename}",
                    ):
                        try:
                            # Verify again immediately before saving.
                            current_integrity = verify_evidence_integrity(
                                manifest["sha256"],
                                result["content"],
                            )

                            if not current_integrity.get(
                                "integrity_verified",
                                False,
                            ):
                                st.error(
                                    "Integrity verification failed. "
                                    "Nothing was registered."
                                )
                            else:
                                saved_count = save_analysis_to_database(
                                    selected_case["id"],
                                    filename,
                                    result,
                                    analysis,
                                )

                                st.session_state.saved_analysis.add(save_key)

                                st.success(
                                    f"Evidence registered. "
                                    f"{saved_count} finding(s) saved."
                                )
                                st.rerun()

                        except Exception as exc:
                            st.error(
                                f"Could not save the analysis: {exc}"
                            )

            except Exception as exc:
                st.error(
                    f"Analysis could not be completed for {filename}: {exc}"
                )


# =========================================================
# 3. INVESTIGATION CASES
# =========================================================

elif page == "Investigation Cases":
    st.header("Investigation Case Management")

    with st.form("create_case_form"):
        case_title = st.text_input("Case Title")
        case_description = st.text_area("Case Description")

        case_priority = st.selectbox(
            "Priority",
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            index=1,
        )

        create_case_clicked = st.form_submit_button(
            "Create Investigation Case"
        )

    if create_case_clicked:
        if not case_title.strip():
            st.error("Enter a case title before continuing.")
        else:
            try:
                new_case = create_case(
                    title=case_title.strip(),
                    description=case_description.strip(),
                    priority=case_priority,
                )

                add_audit_entry(
                    case_id=new_case["id"],
                    action="CASE_CREATED",
                    actor="analyst",
                    details="Investigation case created.",
                )

                st.success(
                    f"Created case {new_case['case_number']}."
                )
                st.rerun()

            except Exception as exc:
                st.error(f"Could not create the case: {exc}")

    st.divider()

    cases = get_case_options()

    if not cases:
        st.info("No investigation cases have been created.")
    else:
        st.subheader("Existing Cases")
        render_dataframe(pd.DataFrame(cases))

        selected_case = st.selectbox(
            "Select a case to inspect",
            options=cases,
            format_func=lambda case: (
                f"{case['case_number']} — {case['title']}"
            ),
            key="case_detail_selection",
        )

        details = get_case_details(selected_case["id"])

        if details:
            case_data = details["case"]

            st.divider()
            st.subheader(
                f"{case_data['case_number']} — {case_data['title']}"
            )

            st.write(
                case_data.get("description") or "No description provided."
            )

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Evidence Records",
                len(details.get("evidence", [])),
            )
            col2.metric(
                "Saved Findings",
                len(details.get("findings", [])),
            )
            col3.metric(
                "Audit Entries",
                len(details.get("audit_entries", [])),
            )

            st.write(
                f"**Priority:** {case_data.get('priority', 'MEDIUM')}"
            )
            st.write(
                f"**Current Status:** {case_data.get('status', 'OPEN')}"
            )

            # Keep case statuses consistent with database/db.py.
            case_statuses = ["OPEN", "IN_PROGRESS", "CLOSED"]
            current_status = case_data.get("status", "OPEN")

            if current_status not in case_statuses:
                current_status = "OPEN"

            with st.form(f"case_status_form_{selected_case['id']}"):
                new_status = st.selectbox(
                    "Case Status",
                    case_statuses,
                    index=case_statuses.index(current_status),
                )

                update_status_clicked = st.form_submit_button(
                    "Update Case Status"
                )

            if update_status_clicked:
                try:
                    update_case_status(
                        case_id=selected_case["id"],
                        status=new_status,
                    )

                    add_audit_entry(
                        case_id=selected_case["id"],
                        action="CASE_STATUS_UPDATED",
                        actor="analyst",
                        details=f"Case status changed to {new_status}.",
                    )

                    st.success("Case status updated.")
                    st.rerun()

                except Exception as exc:
                    st.error(f"Could not update the case status: {exc}")

            with st.expander("Registered Evidence", expanded=True):
                render_dataframe(
                    pd.DataFrame(details.get("evidence", []))
                )

            with st.expander("Saved Security Findings", expanded=True):
                render_dataframe(
                    pd.DataFrame(details.get("findings", []))
                )

            with st.expander("Case Audit Trail"):
                render_dataframe(
                    pd.DataFrame(details.get("audit_entries", []))
                )


# =========================================================
# 4. INCIDENT RESPONSE
# =========================================================

elif page == "Incident Response":
    st.header("Incident Response Management")

    st.write(
        "Create incident records, track their status, and document "
        "response actions. Actions are recorded for investigation; "
        "they do not automatically modify real systems."
    )

    with st.form("create_incident_form"):
        incident_title = st.text_input("Incident Title")

        incident_severity = st.selectbox(
            "Severity",
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            index=1,
        )

        incident_description = st.text_area(
            "Incident Description"
        )

        create_incident_clicked = st.form_submit_button(
            "Create Incident"
        )

    if create_incident_clicked:
        if not incident_title.strip():
            st.error("Enter an incident title.")
        else:
            try:
                incident = create_incident_record(
                    title=incident_title.strip(),
                    severity=incident_severity,
                    description=incident_description.strip(),
                )

                st.success(
                    f"Incident #{incident['id']} created successfully."
                )
                st.rerun()

            except Exception as exc:
                st.error(f"Could not create the incident: {exc}")

    st.divider()
    st.subheader("Saved Incidents")

    incidents = get_incident_options()

    if not incidents:
        st.info("No incidents have been created yet.")
    else:
        selected_incident = st.selectbox(
            "Select an incident",
            options=incidents,
            format_func=lambda incident: (
                f"#{incident['id']} — {incident['title']} "
                f"({incident['status']})"
            ),
            key="incident_selection",
        )

        incident_id = selected_incident["id"]

        # Reload the selected record to obtain its latest saved state.
        incident = next(
            (
                item for item in list_incident_records()
                if item["id"] == incident_id
            ),
            None,
        )

        if incident:
            st.subheader(incident["title"])

            col1, col2 = st.columns(2)

            col1.metric("Severity", incident["severity"])
            col2.metric("Status", incident["status"])

            st.write(
                incident.get("description") or "No description provided."
            )
            st.caption(
                f"Created: {incident.get('created_at', 'N/A')}"
            )

            incident_statuses = [
                "NEW",
                "INVESTIGATING",
                "CONTAINED",
                "RESOLVED",
                "CLOSED",
            ]

            current_status = incident.get("status", "NEW")

            if current_status not in incident_statuses:
                current_status = "NEW"

            st.markdown("#### Update Incident")

            with st.form(f"update_incident_form_{incident_id}"):
                new_incident_status = st.selectbox(
                    "Incident Status",
                    incident_statuses,
                    index=incident_statuses.index(current_status),
                )

                response_action = st.text_input(
                    "Response Action",
                    placeholder=(
                        "Example: Reviewed authentication logs"
                    ),
                )

                response_details = st.text_area(
                    "Action Details"
                )

                update_incident_clicked = st.form_submit_button(
                    "Save Incident Update"
                )

            if update_incident_clicked:
                try:
                    update_incident_record(
                        incident_id=incident_id,
                        status=(
                            new_incident_status
                            if new_incident_status != current_status
                            else None
                        ),
                        action=response_action.strip() or None,
                        details=response_details.strip(),
                        actor="analyst",
                    )

                    st.success("Incident update saved.")
                    st.rerun()

                except Exception as exc:
                    st.error(f"Could not update the incident: {exc}")

            st.markdown("#### Recorded Response Actions")

            actions = incident.get("response_actions") or []

            if actions:
                for index, action in enumerate(actions, start=1):
                    with st.container(border=True):
                        st.markdown(
                            f"**{index}. {action.get('action', 'Action')}**"
                        )
                        st.write(
                            action.get("details") or "No details provided."
                        )
                        st.caption(
                            f"Recorded by: {action.get('actor', 'analyst')}"
                        )
            else:
                st.info("No response actions have been recorded.")


# =========================================================
# 5. REPORTS & AUDIT
# =========================================================

elif page == "Reports & Audit":
    st.header("Investigation Reports & Audit")

    cases = get_case_options()

    if not cases:
        st.info(
            "Create an investigation case before generating a report."
        )
    else:
        selected_case = st.selectbox(
            "Select an investigation case",
            options=cases,
            format_func=lambda case: (
                f"{case['case_number']} — {case['title']}"
            ),
            key="report_case_selection",
        )

        case_id = selected_case["id"]
        details = get_case_details(case_id)

        if details:
            case_data = details["case"]
            evidence_records = details.get("evidence", [])
            findings = details.get("findings", [])
            audit_entries = details.get("audit_entries", [])

            st.subheader("Report Summary")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Evidence Records",
                len(evidence_records),
            )
            col2.metric(
                "Security Findings",
                len(findings),
            )
            col3.metric(
                "Audit Entries",
                len(audit_entries),
            )

            st.write(
                f"**Case Number:** {case_data.get('case_number', 'N/A')}"
            )
            st.write(
                f"**Title:** {case_data.get('title', 'N/A')}"
            )
            st.write(
                f"**Status:** {case_data.get('status', 'N/A')}"
            )

            st.divider()
            st.subheader("Evidence Registry")
            render_dataframe(pd.DataFrame(evidence_records))

            st.subheader("Security Findings")
            render_dataframe(pd.DataFrame(findings))

            st.subheader("Forensic Timeline")

            timeline = get_case_timeline(details)

            if timeline.empty:
                st.info(
                    "No cached timeline is available for this case. "
                    "Open Evidence & Analysis and analyze the relevant "
                    "files in this session to build the timeline."
                )
            else:
                render_dataframe(timeline, max_rows=1000)

            st.divider()
            st.subheader("Generate PDF Report")

            if st.button(
                "Generate Investigation PDF",
                key=f"generate_report_{case_id}",
            ):
                try:
                    pdf_bytes = get_case_report(case_id)

                    st.success(
                        "PDF report generated successfully."
                    )

                except Exception as exc:
                    st.error(
                        f"Could not generate the PDF report: {exc}"
                    )

            report = st.session_state.generated_reports.get(case_id)

            if report:
                st.download_button(
                    label="Download Investigation Report",
                    data=report["bytes"],
                    file_name=(
                        f"cybersentry_case_{case_id}_report.pdf"
                    ),
                    mime="application/pdf",
                    key=f"download_report_{case_id}",
                )

                st.caption(
                    f"Report generated (UTC): {report['generated_at']}"
                )

            st.divider()
            st.subheader("Audit Trail")
            render_dataframe(pd.DataFrame(audit_entries))

            st.subheader("Evidence Fingerprints")

            if evidence_records:
                fingerprints = pd.DataFrame(evidence_records)

                preferred_columns = [
                    column
                    for column in [
                        "filename",
                        "sha256",
                        "file_size",
                        "evidence_status",
                        "recorded_at",
                    ]
                    if column in fingerprints.columns
                ]

                render_dataframe(
                    fingerprints[preferred_columns]
                )
            else:
                st.info(
                    "No evidence has been registered to this case."
                )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "CyberSentry AI — Digital Forensics & Incident Response. "
    "Automated findings are investigative leads that require analyst "
    "validation. Preserve original evidence and use the platform only "
    "with data you are authorized to investigate."
)
