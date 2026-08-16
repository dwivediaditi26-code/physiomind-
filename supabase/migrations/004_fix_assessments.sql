-- ═══════════════════════════════════════════════════════════════
-- PhysioVerse migration 4: fix assessments schema
-- Run once, after migration-3. Only needed because migration-2 already
-- ran on your live project with the wrong assessments shape (guessed
-- ~30 columns before checking real usage — same mistake caught and
-- fixed for consultations/invoices, just missed this table at the time).
-- No real data at risk (test-only clinic) — this drops the old columns.
-- ═══════════════════════════════════════════════════════════════

begin;

alter table assessments add column if not exists data jsonb not null default '{}'::jsonb;

alter table assessments
  drop column if exists mode,
  drop column if exists complaint,
  drop column if exists onset,
  drop column if exists painsite,
  drop column if exists pain,
  drop column if exists aggr,
  drop column if exists reliev,
  drop column if exists history,
  drop column if exists regions,
  drop column if exists region_sides,
  drop column if exists obs,
  drop column if exists palp,
  drop column if exists neuro,
  drop column if exists rom,
  drop column if exists mmt,
  drop column if exists tests,
  drop column if exists func,
  drop column if exists func_other,
  drop column if exists posture,
  drop column if exists gait,
  drop column if exists swelling,
  drop column if exists neuro_note,
  drop column if exists assessment_text,
  drop column if exists problem,
  drop column if exists stg,
  drop column if exists ltg,
  drop column if exists sessions,
  drop column if exists freq,
  drop column if exists modalities,
  drop column if exists exercises,
  drop column if exists home,
  drop column if exists home_freq,
  drop column if exists advice,
  drop column if exists rx;

commit;
