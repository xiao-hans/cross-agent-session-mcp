"""Synthetic regression for URL userinfo masking (`redaction.py:486-489`, `:708-725`).

本轮只验证**合成**输入，不接触真实会话、凭据或用户配置。断言面：

* 连续/重复 `@` 的 userinfo（`https://u:p@@ss@example.test/`）整段遮蔽——空迭代段
  `[^\s/?#@]*+@` 沿到最后一个结构性 `@`，空段之后的 `ss` 不得残留在输出里。
* 普通单 `@` userinfo 同样整段遮蔽，用户名与口令都不外出。
* 主机与路径保持：authority 在 `/` 处终止，路径内的 `@` 不是 userinfo 分隔符，
  不得被遮进主机或路径。
* 幂等重扫：已遮蔽的整段（`user` 恰为占位）不改写、不重复计数。

未在本轮执行（按简报限制：不跑测试、不调用 shell/构建）。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cross_agent_session_mcp.redaction import (
    REDACTION_PLACEHOLDER,
    RedactionStatus,
    _URL_USERINFO_RE,
    _mask_url_userinfo,
    redact_text,
)


class UrlUserinfoRedactionTest(unittest.TestCase):
    """`_mask_url_userinfo` 的替换边界。"""

    def test_consecutive_at_signs_mask_whole_segment(self) -> None:
        """Cursor 疑点：`u:p@@ss@` 的空迭代段必须被吃掉，`ss` 不能留在占位之后。"""
        text, hits = _mask_url_userinfo("https://u:p@@ss@example.test/")

        self.assertEqual(text, f"https://{REDACTION_PLACEHOLDER}@example.test/")
        self.assertEqual(hits, 1)
        for secret in ("u:p", "ss", "@@"):
            self.assertNotIn(secret, text)

    def test_single_at_sign_masks_whole_segment(self) -> None:
        """普通单 `@`：用户名与口令一起进占位段，主机保留。"""
        text, hits = _mask_url_userinfo("https://alice:s3cret@example.test/path")

        self.assertEqual(text, f"https://{REDACTION_PLACEHOLDER}@example.test/path")
        self.assertEqual(hits, 1)
        self.assertNotIn("alice", text)
        self.assertNotIn("s3cret", text)

    def test_host_and_path_are_not_masked_into(self) -> None:
        """匹配止于第一个可判界的结构性 `@`：路径里的 `@` 不受本规则影响。"""
        text, hits = _mask_url_userinfo("https://alice:s3cret@example.test/a@b")

        self.assertEqual(text, f"https://{REDACTION_PLACEHOLDER}@example.test/a@b")
        self.assertEqual(hits, 1)

    def test_rescan_is_idempotent_and_not_double_counted(self) -> None:
        """整段已是纯占位时不改写、不计次（幂等重扫不虚增）。"""
        once, first_hits = _mask_url_userinfo("https://u:p@@ss@example.test/")
        twice, second_hits = _mask_url_userinfo(once)

        self.assertEqual(second_hits, 0)
        self.assertEqual(twice, once)
        self.assertEqual(twice.count(REDACTION_PLACEHOLDER), 1)

    def test_repeated_at_without_credential_content_still_reaches_last_at(self) -> None:
        """多个连续 `@` 时，最后一个 `@` 之前的全部内容都在段内。"""
        text, hits = _mask_url_userinfo("https://a@@@b@example.test/")

        self.assertEqual(text, f"https://{REDACTION_PLACEHOLDER}@example.test/")
        self.assertEqual(hits, 1)
        self.assertNotIn("b@", text)

    def test_empty_userinfo_is_left_untouched(self) -> None:
        """`scheme://@host` 没有可遮蔽的内容：整条失配，原样输出、不计次。"""
        text, hits = _mask_url_userinfo("https://@example.test/")

        self.assertEqual(text, "https://@example.test/")
        self.assertEqual(hits, 0)

    def test_possessive_segments_do_not_backtrack_into_host(self) -> None:
        """段内字符类不含 `/?#@`：正则不可能越过 authority 边界。"""
        self.assertIsNone(_URL_USERINFO_RE.search("https://example.test/no-userinfo"))


class RedactTextUrlUserinfoTest(unittest.TestCase):
    """经完整 `_RULES` 链后的端到端行为（`redaction.py:780-789`）。"""

    def test_pipeline_masks_double_at_userinfo_once(self) -> None:
        outcome = redact_text("见 https://u:p@@ss@example.test/ 结尾")

        self.assertEqual(
            outcome.text,
            f"见 https://{REDACTION_PLACEHOLDER}@example.test/ 结尾",
        )
        self.assertIs(outcome.status, RedactionStatus.REDACTED)
        self.assertEqual(outcome.redacted_count, 1)
        self.assertNotIn("ss@", outcome.text)

    def test_pipeline_rescan_reports_clean_without_new_count(self) -> None:
        """第二轮不应再命中：占位串本身就是可复用的输出形态。"""
        first = redact_text("https://u:p@@ss@example.test/")
        second = redact_text(first.text)

        self.assertEqual(second.text, first.text)
        self.assertEqual(second.redacted_count, 0)
        self.assertIs(second.status, RedactionStatus.CLEAN)


if __name__ == "__main__":
    unittest.main()
