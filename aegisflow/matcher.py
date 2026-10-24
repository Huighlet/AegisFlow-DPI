"""
AegisFlow-DPI: Streaming Aho-Corasick Multi-Pattern Search Engine.
High-throughput string matching algorithm for scanning raw packet payloads against thousands
of signatures in O(n + m) linear time.
"""

from __future__ import annotations

import collections
import dataclasses
from typing import Dict, Generator, List, Optional, Set, Tuple


@dataclasses.dataclass(slots=True)
class AhoNode:
    """Node in the Aho-Corasick Trie Automaton."""
    children: Dict[int, AhoNode] = dataclasses.field(default_factory=dict)
    fail_link: Optional[AhoNode] = None
    output_signatures: List[str] = dataclasses.field(default_factory=list)


class AhoCorasickMatcher:
    """
    Multi-pattern byte-string matching automaton.
    """
    def __init__(self) -> None:
        self.root = AhoNode()
        self._compiled = False
        self._pattern_count = 0

    @property
    def pattern_count(self) -> int:
        return self._pattern_count

    def __len__(self) -> int:
        return self._pattern_count

    def add_pattern(self, pattern: str | bytes, signature_name: str) -> None:
        """Insert a pattern into the trie."""
        pat_bytes = pattern.encode("latin1") if isinstance(pattern, str) else pattern
        if not pat_bytes:
            return

        current = self.root
        for b in pat_bytes:
            if b not in current.children:
                current.children[b] = AhoNode()
            current = current.children[b]

        current.output_signatures.append(signature_name)
        self._pattern_count += 1
        self._compiled = False

    def build_automaton(self) -> None:
        """Construct BFS suffix failure transitions."""
        queue: collections.deque[AhoNode] = collections.deque()

        # Initialize root's immediate children
        for b, child in self.root.children.items():
            child.fail_link = self.root
            queue.append(child)

        while queue:
            current = queue.popleft()

            for b, child in current.children.items():
                queue.append(child)

                # Trace fail transitions
                fail = current.fail_link
                while fail is not None and b not in fail.children:
                    fail = fail.fail_link

                child.fail_link = fail.children[b] if fail is not None else self.root

                # Inherit outputs from failure link
                if child.fail_link and child.fail_link.output_signatures:
                    child.output_signatures.extend(child.fail_link.output_signatures)

        self._compiled = True

    def search(self, payload: bytes) -> List[Tuple[int, str]]:
        """
        Scan raw byte stream and return list of (match_byte_offset, signature_name).
        Executes in O(payload_len) linear time.
        """
        if not self._compiled:
            self.build_automaton()

        matches: List[Tuple[int, str]] = []
        current = self.root

        for idx, byte in enumerate(payload):
            while current is not self.root and byte not in current.children:
                current = current.fail_link or self.root

            if byte in current.children:
                current = current.children[byte]
            else:
                current = self.root

            if current.output_signatures:
                for sig in current.output_signatures:
                    matches.append((idx, sig))

        return matches
