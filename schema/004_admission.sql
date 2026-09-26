-- Admission. Nothing becomes "verified" without a passing verdict row, checked at COMMIT,
-- inside the transaction, for every client. Two calls from an orchestrator cannot be made atomic; one transaction can.
CREATE FUNCTION eval.require_verdict() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, eval AS $$
BEGIN
  IF NEW.status = 'verified'
     AND NOT EXISTS (SELECT 1 FROM eval.verdicts WHERE step_id = NEW.id AND passed) THEN
    RAISE EXCEPTION 'step % cannot be verified: no passing verdict row', NEW.id;
  END IF;
  RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER steps_need_verdict
  AFTER UPDATE OF status ON work.steps
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION eval.require_verdict();
