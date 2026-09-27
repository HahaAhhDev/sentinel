# tiers: warn only tells, auto kills, paranoid locks down

TIERS = ("warn", "auto", "paranoid")


def norm(tier):
    # fold bad input to warn
    t = str(tier or "warn").lower()
    return t if t in TIERS else "warn"


def what(tier):
    # plain words per tier
    t = norm(tier)
    if t == "warn":
        return ["log", "snapshot", "alert"]
    if t == "auto":
        return ["log", "snapshot", "alert", "kill writer", "quarantine binary"]
    return ["log", "snapshot", "alert", "kill writer", "quarantine binary", "suspend rest", "vault restore prompt"]


def kills(tier):
    return norm(tier) in ("auto", "paranoid")


def locks(tier):
    return norm(tier) == "paranoid"
