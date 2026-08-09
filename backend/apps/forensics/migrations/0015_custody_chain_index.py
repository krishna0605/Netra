from django.db import migrations, models


def ordered_chain(events, case_id):
    if not events:
        return []

    roots = [event for event in events if not event.previous_hash]
    if len(roots) != 1:
        raise RuntimeError(
            f"Custody chain migration requires exactly one root for case {case_id}; found {len(roots)}."
        )

    by_hash = {}
    children = {}
    for event in events:
        if event.event_hash in by_hash:
            raise RuntimeError(f"Custody chain migration found a duplicate event hash for case {case_id}.")
        by_hash[event.event_hash] = event
        if event.previous_hash:
            children.setdefault(event.previous_hash, []).append(event)

    ordered = []
    current = roots[0]
    visited = set()
    while current is not None:
        if current.pk in visited:
            raise RuntimeError(f"Custody chain migration found a cycle for case {case_id}.")
        visited.add(current.pk)
        ordered.append(current)
        next_events = children.get(current.event_hash, [])
        if len(next_events) > 1:
            raise RuntimeError(f"Custody chain migration found a branch for case {case_id}.")
        current = next_events[0] if next_events else None

    if len(ordered) != len(events):
        raise RuntimeError(f"Custody chain migration found disconnected events for case {case_id}.")
    return ordered


def backfill_custody_chain_indexes(apps, _schema_editor):
    CustodyLedgerEvent = apps.get_model("forensics", "CustodyLedgerEvent")

    case_ids = CustodyLedgerEvent.objects.order_by().values_list("case_id", flat=True).distinct()
    for case_id in case_ids.iterator():
        events = list(CustodyLedgerEvent.objects.filter(case_id=case_id))
        if not events:
            continue

        ordered = ordered_chain(events, case_id)

        for chain_index, event in enumerate(ordered, start=1):
            event.chain_index = chain_index
        CustodyLedgerEvent.objects.bulk_update(ordered, ["chain_index"])


class Migration(migrations.Migration):
    dependencies = [("forensics", "0014_security_tenancy_and_rate_limits")]

    operations = [
        migrations.AddField(
            model_name="custodyledgerevent",
            name="chain_index",
            field=models.PositiveBigIntegerField(null=True),
        ),
        migrations.RunPython(backfill_custody_chain_indexes, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="custodyledgerevent",
            name="chain_index",
            field=models.PositiveBigIntegerField(),
        ),
        migrations.AddIndex(
            model_name="custodyledgerevent",
            index=models.Index(fields=["case", "chain_index"], name="netra_custody_chain_idx"),
        ),
        migrations.AddConstraint(
            model_name="custodyledgerevent",
            constraint=models.UniqueConstraint(
                fields=("case", "chain_index"), name="netra_custody_case_chain_uniq"
            ),
        ),
        migrations.AddConstraint(
            model_name="custodyledgerevent",
            constraint=models.CheckConstraint(
                condition=models.Q(("chain_index__gte", 1)), name="netra_custody_chain_positive"
            ),
        ),
    ]
