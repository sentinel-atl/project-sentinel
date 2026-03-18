"""
LangChain integration for Sentinel.

Usage:
    from sentinel_atl.langchain import SentinelCallbackHandler

    agent = create_trusted_agent("my-agent")
    handler = SentinelCallbackHandler(agent)

    # Use with any LangChain chain:
    from langchain_openai import ChatOpenAI
    llm = ChatOpenAI(callbacks=[handler])
"""

from __future__ import annotations

from typing import Any, Optional, Sequence, Union
from sentinel_atl.agent import TrustedAgent


class SentinelCallbackHandler:
    """
    LangChain callback handler that logs trust events.
    
    Implements the LangChain BaseCallbackHandler interface shape without
    requiring langchain-core as a hard dependency. When langchain-core is
    installed, this class can be used directly as a callback handler.
    """

    def __init__(
        self,
        agent: TrustedAgent,
        blocked_tools: list[str] | None = None,
        min_reputation: float = 0,
    ):
        self.agent = agent
        self.blocked_tools = set(blocked_tools or [])
        self.min_reputation = min_reputation
        self.name = "SentinelTrustHandler"

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts. Blocks execution if trust check fails."""
        tool_name = serialized.get("name", "unknown")

        if tool_name in self.blocked_tools:
            raise PermissionError(f"Sentinel: Tool '{tool_name}' is blocked by security policy")

        self.agent._audit.log(
            event_type="intent_created",
            actor_did=self.agent.did,
            metadata={"tool": tool_name, "framework": "langchain"},
        )

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool completes successfully."""
        self.agent._audit.log(
            event_type="intent_validated",
            actor_did=self.agent.did,
            result="success",
            metadata={"framework": "langchain"},
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors."""
        self.agent._audit.log(
            event_type="intent_rejected",
            actor_did=self.agent.did,
            result="failure",
            reason=str(error),
            metadata={"framework": "langchain"},
        )

    # ─── Chain callbacks (passthrough) ────────────────────────────

    def on_chain_start(self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        pass

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        pass

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        pass
