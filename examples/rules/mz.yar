rule mz_header
{
  meta:
    severity = "high"
    tag = "quarantine"
  strings:
    $mz = { 4D 5A }
  condition:
    $mz at 0
}
