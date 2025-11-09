# Load Testing for AI Microservice

This directory contains load testing scripts using [Locust](https://locust.io/).

## Prerequisites

```bash
pip install locust
```

## Configuration

Edit `locustfile.py` and update:
- `Authorization` header with your API key
- Endpoint URLs if different from defaults
- Test data as needed

## Running Load Tests

### Basic Load Test
```bash
cd ai-service/tests/load
locust -f locustfile.py --users 50 --spawn-rate 10
```

This will:
- Simulate 50 concurrent users
- Spawn 10 users per second
- Open web UI at http://localhost:8089

### Headless Mode (CI/CD)
```bash
locust -f locustfile.py \
  --users 50 \
  --spawn-rate 10 \
  --run-time 5m \
  --headless \
  --host http://localhost:8002
```

### Custom Configuration
```bash
locust -f locustfile.py \
  --users 100 \
  --spawn-rate 20 \
  --run-time 10m \
  --host http://localhost:8002 \
  --csv results
```

This generates CSV reports: `results_stats.csv`, `results_failures.csv`

## Test Scenarios

### Scenario 1: Normal Load
- **Users**: 50
- **Duration**: 10 minutes
- **Purpose**: Baseline performance

```bash
locust -f locustfile.py --users 50 --spawn-rate 10 --run-time 10m --headless --host http://localhost:8002
```

### Scenario 2: Peak Load
- **Users**: 200
- **Duration**: 5 minutes
- **Purpose**: Stress test

```bash
locust -f locustfile.py --users 200 --spawn-rate 50 --run-time 5m --headless --host http://localhost:8002
```

### Scenario 3: Endurance Test
- **Users**: 100
- **Duration**: 30 minutes
- **Purpose**: Memory leaks, resource exhaustion

```bash
locust -f locustfile.py --users 100 --spawn-rate 20 --run-time 30m --headless --host http://localhost:8002
```

## Task Distribution

Tasks are weighted by frequency:
- `chat_message`: 3x (most common)
- `chat_stream`: 2x
- `dte_validation`: 1x
- `project_matching`: 1x
- `health_check`: 1x (monitoring)

Total weight: 8 tasks per cycle

## Expected Performance

Based on Phase 1 optimization results:

| Metric | Target | Acceptable | Alert |
|--------|--------|------------|-------|
| Response time (p95) | <3s | <5s | >5s |
| Failure rate | 0% | <1% | >1% |
| Requests/sec | 50+ | 30+ | <30 |
| CPU usage | <60% | <80% | >80% |
| Memory usage | <2GB | <3GB | >3GB |

## Monitoring During Tests

### Prometheus Metrics
```bash
# Check metrics while load test runs
curl http://localhost:8002/metrics | grep claude_api
```

### Docker Stats
```bash
# Monitor resource usage
docker stats ai-service
```

### Logs
```bash
# Watch logs for errors
docker logs -f ai-service
```

## Interpreting Results

### Success Criteria
✅ **Pass** if all conditions met:
- p95 latency < 5s
- Failure rate < 1%
- No circuit breaker trips
- Memory usage stable (no leaks)
- Cache hit rate > 70%

### Common Issues

**High Latency**
- Check Claude API rate limits
- Verify Redis connection
- Review prompt caching

**High Failure Rate**
- Check authentication
- Verify endpoint availability
- Review error logs

**Memory Growth**
- Check for session leaks
- Review context cleanup
- Monitor Redis memory

## Cost Estimation

Before running large load tests, estimate cost:

```python
# Example: 50 users, 10 min, 3 req/min/user
users = 50
duration_min = 10
requests_per_min = 3

total_requests = users * duration_min * requests_per_min  # 1,500 requests

# Assume $0.003 per request (with caching)
estimated_cost = total_requests * 0.003  # $4.50
```

**Important**: Use staging environment or low user counts to avoid unexpected costs.

## Advanced Usage

### Custom Scenarios
Create custom scenarios in `locustfile.py`:

```python
@task
def custom_scenario(self):
    """Your custom test"""
    pass
```

### Distributed Load Testing
Run on multiple machines:

```bash
# Master node
locust -f locustfile.py --master

# Worker nodes
locust -f locustfile.py --worker --master-host=<master-ip>
```

## Reports

After running, Locust generates:
- Web UI with real-time charts
- CSV files with detailed statistics
- HTML report (if using --html flag)

```bash
# Generate HTML report
locust -f locustfile.py --users 50 --run-time 5m --headless --html report.html
```

## Troubleshooting

**Connection refused**
```bash
# Verify service is running
docker ps | grep ai-service
curl http://localhost:8002/health
```

**401 Unauthorized**
- Update API key in locustfile.py
- Check Authorization header format

**429 Too Many Requests**
- Reduce users or spawn rate
- Claude API rate limit hit
- Add delays between requests

## Next Steps

1. Run baseline test (50 users)
2. Analyze results
3. Identify bottlenecks
4. Optimize (caching, async, etc.)
5. Re-test and compare
6. Document improvements

## Resources

- [Locust Documentation](https://docs.locust.io/)
- [Best Practices](https://docs.locust.io/en/stable/writing-a-locustfile.html)
- AI Service Metrics: http://localhost:8002/metrics
