# -*- coding: utf-8 -*-
"""
OpenAI GPT-4 Client - Fallback LLM
===================================

Client profesional para OpenAI GPT-4 API.
Usado como fallback cuando Anthropic Claude falla.

Architecture:
- Async/await support (compatible con FastAPI)
- Error handling y logging
- Token usage tracking
- Temperature control
"""

import openai
from typing import List, Dict, Optional
import structlog

logger = structlog.get_logger(__name__)


class OpenAIClient:
    """
    Client for OpenAI GPT-4 API.

    Used as fallback when Anthropic Claude fails or is rate-limited.
    """

    def __init__(self, api_key: str):
        """
        Initialize OpenAI client.

        Args:
            api_key: OpenAI API key
        """
        if not api_key:
            raise ValueError("OpenAI API key is required")

        self.client = openai.AsyncOpenAI(api_key=api_key)
        logger.info("openai_client_initialized")

    async def send_message(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4-turbo-preview",
        max_tokens: int = 2048,
        temperature: float = 0.7
    ) -> Dict:
        """
        Send message to OpenAI API.

        Args:
            messages: List of messages [{role, content}, ...]
                     Roles: 'system', 'user', 'assistant'
            model: Model ID (gpt-4-turbo-preview, gpt-4, gpt-3.5-turbo)
            max_tokens: Max tokens in response
            temperature: Randomness (0-2, default 0.7)

        Returns:
            Dict with 'content' and metadata:
            {
                'content': str,      # Response text
                'model': str,        # Model used
                'usage': {           # Token usage
                    'input_tokens': int,
                    'output_tokens': int,
                    'total_tokens': int
                }
            }

        Raises:
            openai.APIError: If API request fails
        """
        try:
            logger.info("openai_request_started",
                        model=model,
                        message_count=len(messages),
                        max_tokens=max_tokens)

            response = await self.client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature
            )

            result = {
                'content': response.choices[0].message.content,
                'model': model,
                'usage': {
                    'input_tokens': response.usage.prompt_tokens,
                    'output_tokens': response.usage.completion_tokens,
                    'total_tokens': response.usage.total_tokens
                }
            }

            logger.info("openai_request_successful",
                        input_tokens=result['usage']['input_tokens'],
                        output_tokens=result['usage']['output_tokens'])

            return result

        except openai.APIError as e:
            logger.error("openai_api_error",
                        error=str(e),
                        status_code=e.status_code if hasattr(e, 'status_code') else None)
            raise

        except openai.RateLimitError as e:
            logger.error("openai_rate_limit_error", error=str(e))
            raise

        except Exception as e:
            logger.error("openai_unexpected_error", error=str(e))
            raise

    async def send_message_streaming(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4-turbo-preview",
        max_tokens: int = 2048,
        temperature: float = 0.7
    ):
        """
        Send message with streaming response (future implementation).

        Yields:
            Dict chunks with partial content

        TODO: Implement for real-time chat UI
        """
        logger.warning("streaming_not_implemented",
                      message="Streaming support pending implementation")
        raise NotImplementedError("Streaming not yet implemented")


def get_openai_client(api_key: str) -> Optional[OpenAIClient]:
    """
    Factory function for OpenAI client.

    Args:
        api_key: OpenAI API key (optional)

    Returns:
        OpenAIClient instance or None if no API key
    """
    if not api_key:
        logger.warning("openai_client_disabled",
                      message="No OpenAI API key provided - client disabled")
        return None

    return OpenAIClient(api_key)
