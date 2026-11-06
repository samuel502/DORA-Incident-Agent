"""The token pacer (llm/pacing.py): waits before a call that would go over the tokens-per-minute limit."""

from dora_agent.llm.pacing import TokenPacer, estimate_tokens


class FakeTime:
    def __init__(self):
        self.now, self.slept = 0.0, []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_off_when_limit_is_zero():
    t = FakeTime()
    pacer = TokenPacer(0, clock=t.clock, sleep=t.sleep)
    for _ in range(5):
        pacer.wait_for(100_000)
        pacer.record(100_000, 1000)
    assert t.slept == []


def test_waits_only_as_long_as_needed():
    t = FakeTime()
    pacer = TokenPacer(8000, clock=t.clock, sleep=t.sleep)
    pacer.record(3000, 0)  # at 0 s
    t.now = 20.0
    pacer.record(3000, 0)  # at 20 s
    t.now = 30.0
    pacer.wait_for(3000)  # 6,000 + 3,000 > 8,000: wait until the first call is a minute old
    assert len(t.slept) == 1 and abs(t.slept[0] - 30.1) < 0.01
    assert pacer.waited_seconds == t.slept[0]


def test_a_call_bigger_than_the_limit_goes_alone_and_never_waits_forever():
    t = FakeTime()
    pacer = TokenPacer(8000, clock=t.clock, sleep=t.sleep)
    pacer.record(2000, 0)
    pacer.wait_for(20_000)
    assert sum(t.slept) <= 60.2  # waits for the window to empty, then goes


def test_expected_answer_size_counts_too():
    t = FakeTime()
    pacer = TokenPacer(8000, clock=t.clock, sleep=t.sleep)
    pacer.record(4000, 3000)  # 7,000 used; the next answer is expected to be about 3,000 again
    pacer.wait_for(500)
    assert t.slept  # 7,000 + 500 + 3,000 > 8,000


def test_estimate_is_about_four_characters_per_token():
    assert 240 <= estimate_tokens("x" * 1000) <= 260
