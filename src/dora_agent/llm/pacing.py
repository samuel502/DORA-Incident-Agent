"""Token pacing: wait before an LLM call if it would go over the tokens-per-minute limit (config.toml [llm]).

Groq's free tier allows about 8,000 tokens per minute. Every agent step resends the whole conversation,
so one run can go over that on its own. The pacer remembers the tokens used in the last 60 seconds and,
before a call, waits until the call's estimated size fits. That avoids the rate limit instead of
recovering from it. The longest one wait can be is 60 seconds (the window), so runs stay bounded.

Estimate for a call: about 4 characters per token, for the messages and tools sent, plus the answer's
size from the last call. It is a rough guide, not an exact count.
"""

from __future__ import annotations

import json
import time
from collections import deque
from collections.abc import Callable

WINDOW_SECONDS = 60.0
CHARS_PER_TOKEN = 4


def estimate_tokens(payload: object) -> int:
    return len(json.dumps(payload, default=str)) // CHARS_PER_TOKEN + 1


class TokenPacer:
    def __init__(self, tokens_per_minute: int, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self._limit = tokens_per_minute  # 0 = off
        self._clock, self._sleep = clock, sleep
        self._used: deque[tuple[float, int]] = deque()  # (time, tokens)
        self._last_output = 0
        self.waited_seconds = 0.0  # total, for tests and logs

    def _drop_old(self, now: float) -> None:
        while self._used and now - self._used[0][0] >= WINDOW_SECONDS:
            self._used.popleft()

    def wait_for(self, estimated_input: int, deadline: float | None = None) -> bool:
        """Wait until a call of this size fits in the last minute's budget. Never longer than the window.

        deadline: a clock time the wait must not pass (the agent run's time limit), or None.
        Returns True when the call may go ahead, or False, without waiting, if the wait would pass the deadline.
        """
        if self._limit <= 0:
            return True
        needed = estimated_input + self._last_output
        while True:
            now = self._clock()
            self._drop_old(now)
            used = sum(tokens for _, tokens in self._used)
            if not self._used or used + needed <= self._limit:
                return True  # fits, or nothing left to wait for (a call bigger than the limit goes alone)
            pause = WINDOW_SECONDS - (now - self._used[0][0]) + 0.1
            if deadline is not None and now + pause > deadline:
                return False
            self.waited_seconds += pause
            self._sleep(pause)

    def record(self, input_tokens: int, output_tokens: int) -> None:
        self._used.append((self._clock(), input_tokens + output_tokens))
        self._last_output = output_tokens
