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


# ---------- block 6 step 3: the run's time limit ----------


def test_wait_that_would_pass_the_deadline_is_not_started():
    t = FakeTime()
    pacer = TokenPacer(1000, clock=t.clock, sleep=t.sleep)
    pacer.record(900, 0)
    assert pacer.wait_for(500, deadline=t.now + 30) is False  # it would need about 60 s
    assert t.slept == []


def test_wait_that_fits_before_the_deadline_goes_ahead():
    t = FakeTime()
    pacer = TokenPacer(1000, clock=t.clock, sleep=t.sleep)
    pacer.record(900, 0)
    assert pacer.wait_for(500, deadline=t.now + 120) is True
    assert len(t.slept) == 1 and t.slept[0] <= 61


# ---------- calibration (approved by Sam on 11 November 2026) ----------


def test_estimate_is_scaled_by_the_last_real_count():
    t = FakeTime()
    pacer = TokenPacer(8000, clock=t.clock, sleep=t.sleep)
    pacer.record(1500, 0, estimate=2000)  # Groq counted 75 % of the estimate
    t.now = 1.0
    pacer.record(1500, 0, estimate=2000)
    t.now = 2.0
    pacer.wait_for(6000)  # 3,000 used + 6,000 x 0.75 = 7,500: fits, no wait (it waited before)
    assert t.slept == []
    pacer.wait_for(7000)  # 3,000 + 5,250 > 8,000: still waits
    assert t.slept


def test_calibration_is_kept_within_bounds():
    t = FakeTime()
    pacer = TokenPacer(8000, clock=t.clock, sleep=t.sleep)
    pacer.record(10, 0, estimate=10_000)  # a strange count: at most halves the estimate
    t.now = 1.0
    pacer.record(1000, 0)
    pacer.wait_for(14_200)  # 1,010 + 14,200 x 0.5 = 8,110 > 8,000: waits (0.001 would not)
    assert t.slept


def test_without_an_estimate_nothing_is_calibrated():
    t = FakeTime()
    pacer = TokenPacer(8000, clock=t.clock, sleep=t.sleep)
    pacer.record(4000, 0)
    pacer.wait_for(4001)  # unchanged behaviour: 8,001 > 8,000
    assert t.slept
