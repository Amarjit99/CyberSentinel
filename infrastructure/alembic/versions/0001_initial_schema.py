"""0001_initial_schema

Initial migration for CyberSentinel AI PostgreSQL authoritative relational tables.
Governing Decisions: ADR-0001, ADR-0003, ADR-0004, ADR-0006.

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-16 12:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('external_subject', sa.String(length=255), nullable=True),
        sa.Column('display_name', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('idx_users_external_subject', 'users', ['external_subject'], unique=True)

    # 2. roles
    op.create_table(
        'roles',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=64), unique=True, nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True)
    )

    # 3. user_roles
    op.create_table(
        'user_roles',
        sa.Column('user_id', sa.String(length=64), sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('role_id', sa.String(length=64), sa.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('granted_by', sa.String(length=64), nullable=True),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 4. connectors
    op.create_table(
        'connectors',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=128), unique=True, nullable=False),
        sa.Column('type', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='active'),
        sa.Column('config_ref', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 5. events (metadata and raw references)
    op.create_table(
        'events',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('source_id', sa.String(length=64), nullable=False),
        sa.Column('event_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('schema_version', sa.String(length=32), nullable=False, server_default='1.0.0'),
        sa.Column('raw_ref', sa.String(length=255), nullable=False),
        sa.Column('checksum', sa.String(length=64), nullable=False),
        sa.Column('classification', sa.String(length=32), nullable=False, server_default='unclassified'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('idx_events_source_time', 'events', ['source_id', 'event_time'])

    # 6. detections
    op.create_table(
        'detections',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('rule_id', sa.String(length=128), nullable=False),
        sa.Column('rule_version', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='open'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('idx_detections_rule_id', 'detections', ['rule_id'])

    # 7. detection_events
    op.create_table(
        'detection_events',
        sa.Column('detection_id', sa.String(length=64), sa.ForeignKey('detections.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('event_id', sa.String(length=64), primary_key=True),
        sa.Column('relation_type', sa.String(length=64), nullable=False, server_default='matched')
    )

    # 8. incidents (ADR-0001 11-State Check Constraint)
    op.create_table(
        'incidents',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='NEW'),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='medium'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('owner_id', sa.String(length=64), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('NEW', 'TRIAGE', 'INVESTIGATING', 'CONFIRMED', 'BENIGN', "
            "'AWAITING_APPROVAL', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'CLOSED', "
            "'LESSONS_LEARNED', 'REOPENED')",
            name='chk_incident_status_valid'
        )
    )
    op.create_index('idx_incidents_status', 'incidents', ['status'])
    op.create_index('idx_incidents_severity', 'incidents', ['severity'])

    # 9. incident_detections
    op.create_table(
        'incident_detections',
        sa.Column('incident_id', sa.String(length=64), sa.ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('detection_id', sa.String(length=64), sa.ForeignKey('detections.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('link_reason', sa.String(length=255), nullable=False),
        sa.Column('linked_by', sa.String(length=64), nullable=False),
        sa.Column('linked_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 10. incident_entities
    op.create_table(
        'incident_entities',
        sa.Column('incident_id', sa.String(length=64), sa.ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('entity_type', sa.String(length=64), primary_key=True),
        sa.Column('entity_key', sa.String(length=255), primary_key=True),
        sa.Column('relation', sa.String(length=64), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False)
    )

    # 11. evidence
    op.create_table(
        'evidence',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('incident_id', sa.String(length=64), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_type', sa.String(length=64), nullable=False),
        sa.Column('source_ref', sa.String(length=255), nullable=False),
        sa.Column('checksum', sa.String(length=64), nullable=False),
        sa.Column('provenance_json', sa.JSON(), nullable=False),
        sa.Column('classification', sa.String(length=32), nullable=False, server_default='internal'),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(length=64), nullable=False)
    )
    op.create_index('idx_evidence_incident_id', 'evidence', ['incident_id'])

    # 12. incident_notes
    op.create_table(
        'incident_notes',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('incident_id', sa.String(length=64), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('author_id', sa.String(length=64), nullable=False),
        sa.Column('body_redacted', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 13. agent_runs
    op.create_table(
        'agent_runs',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('incident_id', sa.String(length=64), sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('task_type', sa.String(length=64), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False, server_default='QUEUED'),
        sa.Column('model_ref', sa.String(length=128), nullable=False),
        sa.Column('template_version', sa.String(length=32), nullable=False),
        sa.Column('budget_json', sa.JSON(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failure_code', sa.String(length=64), nullable=True)
    )

    # 14. agent_findings
    op.create_table(
        'agent_findings',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('run_id', sa.String(length=64), sa.ForeignKey('agent_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_type', sa.String(length=64), nullable=False),
        sa.Column('claim', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('evidence_refs_json', sa.JSON(), nullable=False),
        sa.Column('limitations', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 15. response_proposals
    op.create_table(
        'response_proposals',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('incident_id', sa.String(length=64), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('action_payload_hash', sa.String(length=64), nullable=False),
        sa.Column('risk', sa.String(length=32), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False, server_default='PENDING'),
        sa.Column('created_by', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("risk IN ('Tier 0', 'Tier 1', 'Tier 2', 'Tier 3')", name='chk_proposal_risk_valid')
    )

    # 16. approvals
    op.create_table(
        'approvals',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('proposal_id', sa.String(length=64), sa.ForeignKey('response_proposals.id', ondelete='CASCADE'), nullable=False),
        sa.Column('approver_id', sa.String(length=64), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('policy_version', sa.String(length=32), nullable=False),
        sa.Column('action_payload_hash', sa.String(length=64), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 17. response_actions
    op.create_table(
        'response_actions',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('proposal_id', sa.String(length=64), sa.ForeignKey('response_proposals.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('idempotency_key', sa.String(length=128), unique=True, nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False, server_default='QUEUED'),
        sa.Column('result_redacted', sa.JSON(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True)
    )

    # 18. audit_events
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('actor_type', sa.String(length=32), nullable=False),
        sa.Column('actor_id', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=128), nullable=False),
        sa.Column('object_type', sa.String(length=64), nullable=False),
        sa.Column('object_id', sa.String(length=64), nullable=False),
        sa.Column('request_id', sa.String(length=64), nullable=True),
        sa.Column('outcome', sa.String(length=32), nullable=False),
        sa.Column('reason_code', sa.String(length=64), nullable=True),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metadata_redacted', sa.JSON(), nullable=False)
    )
    op.create_index('idx_audit_actor_action', 'audit_events', ['actor_id', 'action'])


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('response_actions')
    op.drop_table('approvals')
    op.drop_table('response_proposals')
    op.drop_table('agent_findings')
    op.drop_table('agent_runs')
    op.drop_table('incident_notes')
    op.drop_table('evidence')
    op.drop_table('incident_entities')
    op.drop_table('incident_detections')
    op.drop_table('incidents')
    op.drop_table('detection_events')
    op.drop_table('detections')
    op.drop_table('events')
    op.drop_table('connectors')
    op.drop_table('user_roles')
    op.drop_table('roles')
    op.drop_table('users')
