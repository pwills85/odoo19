# TODOs Found During Unit Test Analysis
## AI Service - anthropic_client.py & chat/engine.py

**Date:** 2025-11-09
**Analysis Tool:** Automated test creation and code analysis
**Status:** CRITICAL - Requires Implementation

---

## SUMMARY

During the creation of comprehensive unit tests for the AI microservice, **1 CRITICAL TODO** was identified that affects confidence scoring throughout the system.

| Priority | Component | Line | Issue | Impact | Fix Effort |
|----------|-----------|------|-------|--------|-----------|
| 🔴 CRITICAL | chat/engine.py | 237 | Hardcoded confidence | Confidence always 95% | 4-8 hours |
| 🔴 CRITICAL | chat/engine.py | 629 | Hardcoded confidence | Streaming confidence always 95% | (same fix) |

---

## CRITICAL TODO #1: Hardcoded Confidence Values

### Location

**File:** `/Users/pedro/Documents/odoo19/ai-service/chat/engine.py`

**Lines:**
- Line 237 (send_message method)
- Line 629 (send_message_stream method)

### Current Implementation

#### In `send_message()` (Line 237):

```python
# 10. Build response
response = ChatResponse(
    message=response_text,
    sources=[doc['title'] for doc in relevant_docs],
    confidence=95.0,  # ❌ TODO: Calculate from LLM confidence scores
    session_id=session_id,
    llm_used=llm_used,
    tokens_used=tokens_used,
    plugin_used=plugin_module
)
```

#### In `send_message_stream()` (Line 629):

```python
# 9. Yield completion metadata
yield {
    "type": "done",
    "metadata": {
        "sources": [doc['title'] for doc in relevant_docs],
        "confidence": 95.0,  # ❌ TODO: Hardcoded
        "llm_used": "anthropic",
        "tokens_used": tokens_used,
        "session_id": session_id
    }
}
```

### Issue Description

**Problem:** Confidence value is hardcoded to 95.0 instead of being calculated from the actual LLM response.

**Root Cause:** Initial implementation used placeholder value pending proper confidence calculation algorithm.

**Impact:**
1. **Accuracy Loss:** All confidence values returned to clients are inaccurate
2. **Decision Making:** Upstream systems cannot differentiate high-confidence from low-confidence responses
3. **User Experience:** Users get false sense of security in AI responses
4. **Compliance:** May violate AI transparency requirements
5. **Debugging:** Impossible to trace response quality issues

### Example Impact

```python
# Current behavior
response = await chat_engine.send_message(
    session_id="session-1",
    user_message="¿Es válido este DTE?"
)
print(response.confidence)  # Always 95.0 ❌
print(f"Confidence: {response.confidence}%")  # "Confidence: 95.0%" ❌

# Desired behavior
response = await chat_engine.send_message(
    session_id="session-1",
    user_message="¿Es válido este DTE?"
)
print(response.confidence)  # Could be 75.2, 89.5, 45.0, etc. ✅
print(f"Confidence: {response.confidence}%")  # "Confidence: 75.2%" ✅
```

---

## SOLUTION OPTIONS

### Option 1: Extract from Anthropic Response Metadata (RECOMMENDED)

**Effort:** 4-6 hours
**Complexity:** Medium
**Pros:** Uses built-in LLM metrics
**Cons:** Anthropic API doesn't provide direct confidence metric

```python
async def _calculate_confidence_from_response(self, response: Message) -> float:
    """
    Calculate confidence based on response characteristics.

    Factors:
    - Response length (longer often = more certain)
    - Token count predictability
    - Parsing success
    - Semantic coherence
    """
    try:
        # Factor 1: Completeness (is response full sentence?)
        response_text = response.content[0].text
        completeness_score = (
            100 if response_text.endswith('.')
            else 80 if response_text.endswith('!')
            else 60
        )

        # Factor 2: Output token ratio (actual vs predicted)
        output_tokens = response.usage.output_tokens
        predicted_tokens = self.max_tokens * 0.3
        ratio_score = min(100, (output_tokens / max(1, predicted_tokens)) * 100)

        # Factor 3: Stop reason (if available)
        stop_reason = getattr(response, 'stop_reason', None)
        stop_score = 95 if stop_reason == "end_turn" else 70

        # Weighted average
        confidence = (
            completeness_score * 0.3 +
            ratio_score * 0.3 +
            stop_score * 0.4
        )

        return min(100, max(0, confidence))

    except Exception as e:
        logger.error("confidence_calculation_failed", error=str(e))
        return 50.0  # Neutral default
```

**Implementation in `send_message()`:**

```python
# 6. Call LLM (Anthropic primary)
llm_used = 'anthropic'
tokens_used = None

try:
    response_text, tokens_used = await self._call_anthropic(
        system_prompt,
        history[-self.max_context_messages:]
    )

    # ✅ Calculate confidence from response
    confidence = await self._calculate_confidence_from_response(response)

except Exception as e:
    logger.error("anthropic_failed_no_fallback", ...)
    raise

# 10. Build response
response = ChatResponse(
    message=response_text,
    sources=[doc['title'] for doc in relevant_docs],
    confidence=confidence,  # ✅ Use calculated value
    session_id=session_id,
    llm_used=llm_used,
    tokens_used=tokens_used,
    plugin_used=plugin_module
)
```

---

### Option 2: Use Semantic Similarity Scoring

**Effort:** 6-8 hours
**Complexity:** High
**Pros:** Detects hallucinations, measures coherence
**Cons:** Requires ML model integration

```python
async def _calculate_confidence_semantic(self, response_text: str, context: Dict) -> float:
    """
    Calculate confidence using semantic similarity to expected response patterns.

    Requires: sentence-transformers (already in requirements)
    """
    from sentence_transformers import util
    from utils.embeddings import get_embedding_model

    try:
        embedder = get_embedding_model()

        # Embed response
        response_embedding = embedder.encode(response_text, convert_to_tensor=True)

        # Embed system prompt / expected patterns
        expected_patterns = self._get_expected_patterns(context)
        expected_embedding = embedder.encode(expected_patterns, convert_to_tensor=True)

        # Calculate similarity (0-1)
        similarity = float(util.pytorch_cos_sim(response_embedding, expected_embedding))

        # Convert to confidence (0-100)
        confidence = similarity * 100

        return min(100, max(0, confidence))

    except Exception as e:
        logger.error("semantic_confidence_failed", error=str(e))
        return 50.0
```

---

### Option 3: Use Plugin-Based Confidence

**Effort:** 3-4 hours
**Complexity:** Low
**Pros:** Plugin-specific confidence calculation
**Cons:** Requires plugin changes

```python
async def _calculate_confidence_from_plugin(self, plugin, response_text: str) -> float:
    """
    Ask plugin to evaluate its own response confidence.
    """
    if not plugin:
        return 50.0  # Neutral for non-plugin responses

    try:
        # Some plugins might implement confidence scoring
        if hasattr(plugin, 'calculate_response_confidence'):
            return await plugin.calculate_response_confidence(response_text)
        else:
            return 50.0  # Default neutral

    except Exception as e:
        logger.error("plugin_confidence_failed", error=str(e))
        return 50.0
```

---

### Option 4: User Feedback-Based Confidence

**Effort:** 8-10 hours
**Complexity:** High
**Pros:** Real user validation
**Cons:** Requires user feedback mechanism

```python
async def _calculate_confidence_from_feedback(self, session_id: str) -> float:
    """
    Calculate confidence based on historical user feedback.

    Requires:
    - Feedback collection mechanism
    - Response quality database
    - Similarity matching algorithm
    """
    try:
        # Get similar past responses
        similar_responses = await self.response_db.find_similar(
            message=self.last_message,
            limit=10
        )

        if not similar_responses:
            return 50.0  # No history

        # Average feedback scores
        feedback_scores = [r.user_rating for r in similar_responses if r.user_rating]
        if not feedback_scores:
            return 50.0

        return sum(feedback_scores) / len(feedback_scores)

    except Exception as e:
        logger.error("feedback_confidence_failed", error=str(e))
        return 50.0
```

---

## RECOMMENDED SOLUTION

**Option 1 (Extract from Response Metadata)** is recommended because:

1. ✅ **Fastest to implement** (4-6 hours)
2. ✅ **No new dependencies** (already have response object)
3. ✅ **Works with current architecture** (no plugin changes)
4. ✅ **Sufficient accuracy** for most use cases
5. ✅ **Easy to enhance later** (can combine with other options)

---

## IMPLEMENTATION PLAN

### Phase 1: Create Confidence Calculator (2 hours)

**File:** `chat/engine.py` - Add new method

```python
async def _calculate_confidence_from_response(
    self,
    response_text: str,
    response_metadata: Dict
) -> float:
    """Calculate confidence from response characteristics."""
    # Implementation per Option 1 above
```

### Phase 2: Integrate into send_message() (1 hour)

**File:** `chat/engine.py` - Update line 237

```python
# Before
confidence=95.0,  # TODO

# After
confidence=calculated_confidence_value,
```

### Phase 3: Integrate into send_message_stream() (1 hour)

**File:** `chat/engine.py` - Update line 629

```python
# Before
"confidence": 95.0,  # TODO

# After
"confidence": calculated_confidence_value,
```

### Phase 4: Update Tests (1-2 hours)

**File:** `tests/unit/test_chat_engine.py`

Update:
- `test_send_message_confidence_hardcoded_todo`
- `test_send_message_stream_confidence_hardcoded_todo`

```python
@pytest.mark.unit
@pytest.mark.asyncio
async def test_send_message_confidence_calculated(self, chat_engine):
    """Test confidence is properly calculated from response"""
    response = await chat_engine.send_message(...)

    # New assertion instead of hardcoded check
    assert response.confidence > 0
    assert response.confidence <= 100
    assert response.confidence != 95.0  # Not hardcoded
```

### Phase 5: Integration Testing (2 hours)

**File:** `tests/integration/test_chat_engine_confidence.py` (new)

```python
@pytest.mark.integration
async def test_confidence_varies_with_response_quality():
    """Test that different response types get different confidence"""
    # Good response
    response1 = await engine.send_message("Simple question")

    # Complex response
    response2 = await engine.send_message("Complex question")

    # Confidence should vary
    assert response1.confidence != response2.confidence
```

**Total Time:** 7-10 hours

---

## TESTING THE FIX

### Unit Tests

```python
@pytest.mark.unit
@pytest.mark.asyncio
async def test_confidence_calculation():
    """Verify confidence is calculated, not hardcoded"""
    engine = ChatEngine(...)
    response = await engine.send_message(
        session_id="test",
        user_message="¿Qué es un DTE?"
    )

    # Should NOT be hardcoded
    assert response.confidence != 95.0

    # Should be in valid range
    assert 0 <= response.confidence <= 100

    # Should be float
    assert isinstance(response.confidence, (int, float))
```

### Integration Tests

```python
@pytest.mark.integration
async def test_confidence_varies():
    """Verify different responses get different confidences"""
    engine = ChatEngine(...)

    responses = []
    for msg in [
        "Hola",
        "¿Cómo valido un DTE con número folio inválido?",
        "123abc",
    ]:
        r = await engine.send_message(session_id="test", user_message=msg)
        responses.append(r.confidence)

    # Confidence should vary
    assert len(set(responses)) > 1, "All responses have same confidence"
```

---

## ACCEPTANCE CRITERIA

When implementing this fix:

- [ ] Confidence is calculated from response characteristics (not hardcoded)
- [ ] Confidence values vary between 0-100 based on response quality
- [ ] Unit tests pass (updated tests)
- [ ] Integration tests pass (new tests)
- [ ] No regression in existing functionality
- [ ] Documentation updated with algorithm explanation
- [ ] Code follows project style guidelines
- [ ] Performance impact is <10% overhead

---

## MIGRATION PATH

For existing systems using hardcoded confidence=95.0:

```python
# Backward compatibility wrapper
def get_confidence_compat(response: ChatResponse) -> float:
    """
    Get confidence with backward compatibility.

    Before: Always returns 95.0
    After: Returns calculated value (0-100)
    """
    return response.confidence
```

Update clients gradually:

```python
# Phase 1: Accept new calculated values
if response.confidence < 80:
    log_warning("Low confidence response")

# Phase 2: Act on new values
if response.confidence < 50:
    require_human_review = True

# Phase 3: Remove hardcoded assumptions
assert response.confidence != 95.0, "Still hardcoded?"
```

---

## REFERENCES

**Related Documentation:**
- Anthropic API Reference: https://docs.anthropic.com/claude/reference/getting-started
- ChatEngine Source: `/Users/pedro/Documents/odoo19/ai-service/chat/engine.py`
- Test Cases: `/Users/pedro/Documents/odoo19/ai-service/tests/unit/test_chat_engine.py`

**Test References:**
- `test_send_message_confidence_hardcoded_todo` (line XXX)
- `test_send_message_stream_confidence_hardcoded_todo` (line XXX)

---

## PRIORITY & SCHEDULE

### Priority: 🔴 CRITICAL

**Reason:** Affects all chat responses returned to users
**Impact:** Confidence values mislead users and upstream systems
**Risk:** Data integrity, user trust, compliance

### Recommended Schedule

- **Week 1:** Phase 1-2 (4 hours) - Implement and integrate calculator
- **Week 1:** Phase 3-4 (2 hours) - Update tests
- **Week 2:** Phase 5 (2 hours) - Integration testing
- **Week 2:** Code review and merge
- **Week 3:** Monitor in production

---

## SECONDARY IMPROVEMENTS

While implementing the fix, consider:

1. **Add confidence logging:** Log calculated vs expected confidence
2. **Add metrics:** Track confidence distribution
3. **Add debugging:** Include confidence factors in response metadata
4. **Add configuration:** Make confidence calculation algorithm configurable
5. **Add thresholds:** Define confidence thresholds for different actions

---

## CONCLUSION

**Status:** 1 CRITICAL TODO identified and documented
**Severity:** High (affects all responses)
**Effort:** 7-10 hours to fix
**Impact:** Significant accuracy improvement
**Recommendation:** Implement in next sprint

This is the **only TODO** found in the codebase during comprehensive testing. Once fixed, the AI service will have proper confidence scoring throughout.

---

**Report Generated:** 2025-11-09
**Status:** READY FOR IMPLEMENTATION
**Next Step:** Assign to development team and schedule implementation
