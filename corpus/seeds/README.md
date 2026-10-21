Seed corpus for `net_fuzzer`: binary protobuf `Session` messages.

The set was distilled from a fuzzing campaign with `-set_cover_merge=1`, so it
is the smallest subset that keeps every coverage feature of the full corpus,
and then filtered to inputs that run without crashing. A crash-free seed set
matters for coverage measurement: `scripts/coverage_report.sh` runs it to
produce the numbers in the README and in CI.

`scripts/campaign.sh` reads this directory as extra seeds, so a new campaign
does not start from an empty corpus.

The files are encoded against `fuzz/net_fuzzer.proto`. After a change that
alters the wire format of existing fields, regenerate the set:

    ./net_fuzzer -set_cover_merge=1 new_seeds/ campaign/corpus/
    # keep only inputs that exit 0 when run one by one, then replace this set
