# -*- coding: utf-8 -*-
"""
Context Manager - Redis-based Session and Conversation History
===============================================================

Professional session management for multi-turn conversations.

Storage Strategy:
- Session history: Redis hash (session:{id}:history)
- User context: Redis hash (session:{id}:context)
- TTL: 1 hour (configurable)
- Auto-cleanup on expiration

Architecture:
- Stateless (all state in Redis)
- Scalable (multiple AI service instances)
- Fast (Redis in-memory)
"""

import redis
import json
from typing import List, Dict, Optional
from datetime import timedelta, datetime
import structlog

logger = structlog.get_logger(__name__)


class ContextManager:
    """
    Manages user sessions and conversation history using Redis.

    Features:
    - Multi-turn conversation history
    - User context (company_id, user_role, permissions)
    - Automatic TTL and cleanup
    - JSON serialization
    - Error resilience
    """

    def __init__(self, redis_client: redis.Redis, ttl_seconds: int = 3600):
        """
        Initialize context manager.

        Args:
            redis_client: Redis client instance
            ttl_seconds: Time-to-live for sessions (default 1 hour)
        """
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds
        logger.info("context_manager_initialized", ttl_seconds=ttl_seconds)

    def get_conversation_history(self, session_id: str) -> List[Dict]:
        """
        Retrieve conversation history for session.

        Args:
            session_id: Unique session identifier

        Returns:
            List of messages [{role, content, timestamp}, ...]
            Empty list if no history or error
        """
        key = f"session:{session_id}:history"

        try:
            data = self.redis.get(key)
            if data:
                history = json.loads(data)
                logger.info("conversation_history_retrieved",
                           session_id=session_id,
                           message_count=len(history))
                return history

            logger.info("conversation_history_empty", session_id=session_id)
            return []

        except json.JSONDecodeError as e:
            logger.error("conversation_history_decode_error",
                        session_id=session_id,
                        error=str(e))
            return []

        except Exception as e:
            logger.error("conversation_history_retrieval_error",
                        session_id=session_id,
                        error=str(e))
            return []

    def save_conversation_history(
        self,
        session_id: str,
        messages: List[Dict]
    ):
        """
        Save conversation history to Redis with TTL.

        Args:
            session_id: Session identifier
            messages: List of messages to save
        """
        key = f"session:{session_id}:history"

        try:
            # Add timestamps if not present
            for msg in messages:
                if 'timestamp' not in msg:
                    msg['timestamp'] = datetime.utcnow().isoformat()

            # Serialize and save
            self.redis.setex(
                key,
                self.ttl_seconds,
                json.dumps(messages, ensure_ascii=False)
            )

            logger.info("conversation_history_saved",
                       session_id=session_id,
                       message_count=len(messages),
                       ttl_seconds=self.ttl_seconds)

        except Exception as e:
            logger.error("conversation_history_save_error",
                        session_id=session_id,
                        error=str(e))

    def clear_session(self, session_id: str):
        """
        Delete all session data (history + context).

        Args:
            session_id: Session identifier
        """
        history_key = f"session:{session_id}:history"
        context_key = f"session:{session_id}:context"

        try:
            deleted = self.redis.delete(history_key, context_key)
            logger.info("session_cleared",
                       session_id=session_id,
                       keys_deleted=deleted)

        except Exception as e:
            logger.error("session_clear_error",
                        session_id=session_id,
                        error=str(e))

    def get_user_context(self, session_id: str) -> Optional[Dict]:
        """
        Get user context (company, role, permissions, etc.).

        Args:
            session_id: Session identifier

        Returns:
            Dict with user context or None
        """
        key = f"session:{session_id}:context"

        try:
            data = self.redis.get(key)
            if data:
                context = json.loads(data)
                logger.info("user_context_retrieved",
                           session_id=session_id,
                           company_id=context.get('company_id'))
                return context

            return None

        except Exception as e:
            logger.error("user_context_retrieval_error",
                        session_id=session_id,
                        error=str(e))
            return None

    def save_user_context(self, session_id: str, context: Dict):
        """
        Save user context to Redis.

        Args:
            session_id: Session identifier
            context: User context dict (company_id, user_role, etc.)
        """
        key = f"session:{session_id}:context"

        try:
            self.redis.setex(
                key,
                self.ttl_seconds,
                json.dumps(context, ensure_ascii=False)
            )

            logger.info("user_context_saved",
                       session_id=session_id,
                       company_id=context.get('company_id'))

        except Exception as e:
            logger.error("user_context_save_error",
                        session_id=session_id,
                        error=str(e))

    def extend_session_ttl(self, session_id: str):
        """
        Extend session TTL (refresh on activity).

        Args:
            session_id: Session identifier
        """
        history_key = f"session:{session_id}:history"
        context_key = f"session:{session_id}:context"

        try:
            self.redis.expire(history_key, self.ttl_seconds)
            self.redis.expire(context_key, self.ttl_seconds)

            logger.debug("session_ttl_extended",
                        session_id=session_id,
                        ttl_seconds=self.ttl_seconds)

        except Exception as e:
            logger.error("session_ttl_extension_error",
                        session_id=session_id,
                        error=str(e))

    def get_session_stats(self, session_id: str) -> Dict:
        """
        Get session statistics.

        Args:
            session_id: Session identifier

        Returns:
            Dict with stats (message_count, ttl_remaining, etc.)
        """
        history_key = f"session:{session_id}:history"

        try:
            # Get history
            history = self.get_conversation_history(session_id)

            # Get TTL
            ttl = self.redis.ttl(history_key)

            return {
                'session_id': session_id,
                'message_count': len(history),
                'ttl_remaining_seconds': ttl if ttl > 0 else 0,
                'exists': ttl > 0
            }

        except Exception as e:
            logger.error("session_stats_error",
                        session_id=session_id,
                        error=str(e))
            return {
                'session_id': session_id,
                'message_count': 0,
                'ttl_remaining_seconds': 0,
                'exists': False,
                'error': str(e)
            }
