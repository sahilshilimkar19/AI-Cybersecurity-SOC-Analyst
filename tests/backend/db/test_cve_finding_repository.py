"""Integration tests for persisting CVE findings.

Requires ``SOC_TEST_DATABASE_URL``; skipped otherwise. Two properties are under
test: candidates survive the write, and a re-run supersedes as a whole dossier
rather than as a scatter of independently-versioned rows.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from backend.db.orm.investigation import Investigation
from backend.db.repositories.analysis import CveFindingRepository
from backend.services.vulnerability import record_cve_findings, to_cve_finding
from models.enums import CveApplicability, TriggerSource
from models.values import Citation
from models.vulnerability import (
    AffectedRange,
    ApplicabilityEvidence,
    ApplicabilityReason,
    AssetContext,
    AssetSoftware,
    CveAssessment,
    CveRecord,
    CveResearchRequest,
    CveResearchResult,
    ExploitMapping,
)
from tools.cvss import interpret
from tools.versions import assess_applicability

LOG4SHELL = CveRecord(
    cve_id="CVE-2021-44228",
    summary="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
    cvss=interpret("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", reported_score=10.0),
    cwe_ids=["CWE-502"],
    affected=[
        AffectedRange(
            product="log4j", version_start_including="2.0", version_end_excluding="2.15.0"
        )
    ],
    published_at=datetime(2021, 12, 10, tzinfo=UTC),
    modified_at=datetime(2023, 11, 7, tzinfo=UTC),
)


@pytest.fixture
def investigation(db_session: Session) -> Investigation:
    record = Investigation(trigger_source=TriggerSource.ALERT, title="cve fixture")
    db_session.add(record)
    db_session.flush()
    return record


def _confirmed() -> CveAssessment:
    applicability, evidence = assess_applicability(
        LOG4SHELL,
        [
            AssetContext(
                hostname="web-01",
                software=[AssetSoftware(product="Apache Log4j", version="2.14.1")],
            )
        ],
    )
    assert applicability is CveApplicability.CONFIRMED
    return CveAssessment(
        record=LOG4SHELL,
        applicability=applicability,
        evidence=evidence,
        exploit_mapping=ExploitMapping(
            technique_ids=["T1059"],
            signal_rule_ids=["encoded_command_execution"],
            event_ids=["evt-1"],
            rationale="an affected product appears in the observed indicators",
        ),
        citations=[
            Citation(
                source_id="nvd",
                source="NVD",
                url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            )
        ],
        confidence=0.95,
    )


def _candidate() -> CveAssessment:
    return CveAssessment(
        record=LOG4SHELL.model_copy(update={"cve_id": "CVE-2022-3602", "cvss": None}),
        applicability=CveApplicability.CANDIDATE,
        evidence=[
            ApplicabilityEvidence(
                reason=ApplicabilityReason.VERSION_UNKNOWN,
                hostname="web-02",
                product="openssl",
                detail="web-02 runs openssl but the inventory records no version",
            )
        ],
        citations=[Citation(source_id="nvd", source="NVD")],
        confidence=0.5,
    )


def _result(*assessments: CveAssessment, stale: bool = False) -> CveResearchResult:
    return CveResearchResult(
        investigation_id="inv-1",
        cves=[item for item in assessments if item.is_confirmed],
        candidates=[
            item for item in assessments if item.applicability is CveApplicability.CANDIDATE
        ],
        stale=stale,
    )


def test_a_confirmed_finding_round_trips_with_its_reasoning(
    db_session: Session, investigation: Investigation
) -> None:
    (row,) = record_cve_findings(db_session, investigation.id, _result(_confirmed()))

    assert row.cve_id == "CVE-2021-44228"
    assert row.applicability is CveApplicability.CONFIRMED
    assert "2.14.1" in (row.summary or "")
    assert row.source_freshness == LOG4SHELL.modified_at


def test_candidates_are_persisted_not_discarded(
    db_session: Session, investigation: Investigation
) -> None:
    """Storing only confirmations throws away the entire work list."""
    rows = record_cve_findings(db_session, investigation.id, _result(_confirmed(), _candidate()))

    assert {row.cve_id for row in rows} == {"CVE-2021-44228", "CVE-2022-3602"}
    candidate = next(row for row in rows if row.cve_id == "CVE-2022-3602")
    assert candidate.applicability is CveApplicability.CANDIDATE


def test_the_applicability_reason_is_stored_with_the_finding(
    db_session: Session, investigation: Investigation
) -> None:
    """A row saying "candidate" without saying why is unactionable later."""
    rows = record_cve_findings(db_session, investigation.id, _result(_candidate()))
    assert "version_unknown" in (rows[0].summary or "")


def test_cvss_is_stored_with_its_vector_and_plain_reading(
    db_session: Session, investigation: Investigation
) -> None:
    (row,) = record_cve_findings(db_session, investigation.id, _result(_confirmed()))

    assert row.cvss is not None
    assert row.cvss["score"] == 10.0
    assert row.cvss["vector"].startswith("CVSS:3.1/")
    assert "over the network" in row.cvss["narrative"]


def test_citations_travel_with_the_row(db_session: Session, investigation: Investigation) -> None:
    (row,) = record_cve_findings(db_session, investigation.id, _result(_confirmed()))
    assert row.citations[0]["url"].endswith("/CVE-2021-44228")


def test_the_exploit_mapping_is_stored_only_when_something_connects(
    db_session: Session, investigation: Investigation
) -> None:
    rows = record_cve_findings(db_session, investigation.id, _result(_confirmed(), _candidate()))
    by_id = {row.cve_id: row for row in rows}

    assert by_id["CVE-2021-44228"].exploit_mapping[0]["technique_ids"] == ["T1059"]
    assert by_id["CVE-2022-3602"].exploit_mapping == []


def test_a_stale_dossier_says_so_in_the_stored_summary(
    db_session: Session, investigation: Investigation
) -> None:
    stale_record = LOG4SHELL.model_copy(update={"stale": True})
    assessment = _candidate().model_copy(update={"record": stale_record})
    (row,) = record_cve_findings(db_session, investigation.id, _result(assessment, stale=True))

    assert "indexed corpus" in (row.summary or "")


def test_a_re_run_supersedes_the_whole_dossier(
    db_session: Session, investigation: Investigation
) -> None:
    record_cve_findings(db_session, investigation.id, _result(_candidate()))
    second = record_cve_findings(db_session, investigation.id, _result(_confirmed(), _candidate()))

    assert {row.version for row in second} == {2}
    repository = CveFindingRepository(db_session)
    assert repository.latest_version(investigation.id) == 2
    assert len(repository.current(investigation.id)) == 2


def test_a_prior_generation_can_be_read_back_whole(
    db_session: Session, investigation: Investigation
) -> None:
    """ "What did we believe on Tuesday" has to be answerable as one dossier."""
    record_cve_findings(db_session, investigation.id, _result(_candidate()))
    record_cve_findings(db_session, investigation.id, _result(_confirmed(), _candidate()))

    repository = CveFindingRepository(db_session)
    first = repository.for_version(investigation.id, 1)
    assert [row.cve_id for row in first] == ["CVE-2022-3602"]


def test_an_investigation_with_no_research_reports_nothing(
    db_session: Session, investigation: Investigation
) -> None:
    repository = CveFindingRepository(db_session)
    assert repository.current(investigation.id) == []
    assert repository.latest_version(investigation.id) == 0


def test_an_empty_dossier_writes_no_rows(db_session: Session, investigation: Investigation) -> None:
    assert record_cve_findings(db_session, investigation.id, _result()) == []


def test_versions_are_isolated_per_investigation(db_session: Session) -> None:
    first = Investigation(trigger_source=TriggerSource.ALERT, title="one")
    second = Investigation(trigger_source=TriggerSource.ALERT, title="two")
    db_session.add_all([first, second])
    db_session.flush()

    record_cve_findings(db_session, first.id, _result(_confirmed()))
    record_cve_findings(db_session, first.id, _result(_confirmed()))
    (row,) = record_cve_findings(db_session, second.id, _result(_confirmed()))

    assert row.version == 1


def test_mapping_is_pure_and_does_not_touch_the_session() -> None:
    from uuid import uuid4

    row = to_cve_finding(uuid4(), _confirmed(), version=4)
    assert row.version == 4
    assert row.applicability is CveApplicability.CONFIRMED


def test_the_request_contract_accepts_the_graph_payload_shape() -> None:
    """The node passes serialized state; the contract has to take it as-is."""
    request = CveResearchRequest(
        investigation_id="inv-1",
        threat_assessment={"verdict": "malicious"},
        assets=[AssetContext(hostname="web-01")],
    )
    assert request.assets[0].software == []
