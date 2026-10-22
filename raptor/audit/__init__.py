"""raptor/audit: the Company Audit, a short report about a company's website, domain, email set-up and online visibility.

The one rule: a finding is only shown if it was MEASURED and can be shown. Every check ends in one of five results (common.py):
pass / warn / issue are measured facts; info is a measured fact that is not a problem; unknown means we could not check (the site refused,
a service was down, or the method cannot prove it) and is never counted against the company. Every check carries its value, its source,
the time, and a "verify it yourself" line.
"""
