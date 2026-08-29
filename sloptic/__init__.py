"""Sloptic, a grader that measures how well any deployed web app holds up.

Points at a live URL, or deploys a submission to one, discovers the surface, runs the
applicable catalog probes, and sums their penalties into a slop score. The deploy step sits
behind a Deployer, so the same pipeline runs against a local subprocess (dev and CI, for
trusted reference apps) or a sandboxed Docker container (production, for untrusted submissions).
"""
