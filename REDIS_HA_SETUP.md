# Redis High Availability Setup

**Implementado:** 2025-11-09
**Arquitectura:** Redis Sentinel (1 Master + 2 Replicas + 3 Sentinels)
**Proyecto:** Odoo 19 Stack - Chilean Localization

---

## Arquitectura

```
┌─────────────────────────────────────────────┐
│              Redis Sentinel Layer           │
│          (Service Discovery + Failover)     │
│                                             │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐
│  │ Sentinel 1 │  │ Sentinel 2 │  │ Sentinel 3 │
│  │  :26379    │  │  :26379    │  │  :26379    │
│  └────────────┘  └────────────┘  └────────────┘
│        │               │               │
└────────┼───────────────┼───────────────┼────────┘
         │               │               │
         ▼               ▼               ▼
   ┌─────────┐    ┌──────────┐    ┌──────────┐
   │ Master  │───▶│ Replica 1│    │ Replica 2│
   │ (R/W)   │    │ (R-only) │◀───│ (R-only) │
   │ :6379   │    │ :6379    │    │ :6379    │
   └─────────┘    └──────────┘    └──────────┘
       │               │               │
       ▼               ▼               ▼
   [RDB+AOF]       [AOF]           [AOF]
```

**Components:**

- **3 Sentinel Nodes:** Monitor master, detect failures, orchestrate failover
- **1 Master Node:** Handles read/write operations
- **2 Replica Nodes:** Handle read operations, ready for promotion
- **Quorum:** 2/3 Sentinels must agree to declare master down

---

## Features

### High Availability
- **Automatic Failover:** <10 seconds detection + promotion
- **Service Discovery:** Clients connect via Sentinel (dynamic master discovery)
- **Data Replication:** Synchronous replication to 1+ replicas before ACK
- **Health Checks:** All nodes monitored every 10 seconds

### Data Persistence
- **RDB Snapshots:** Point-in-time backups (900s/1key, 300s/10keys, 60s/10000keys)
- **AOF (Append Only File):** Every second fsync for durability
- **Hybrid Persistence:** RDB + AOF enabled on master

### Performance
- **Read Scaling:** 2 replicas available for read operations
- **Memory Management:** 512MB max per node, LRU eviction policy
- **Connection Pooling:** Health checks every 30 seconds
- **Replication:** Async with min-replicas-to-write = 1

### Security
- **Password Authentication:** All nodes require password
- **Network Isolation:** Only exposed on internal Docker network
- **No External Ports:** All communication internal to stack_network

---

## Configuration

### Docker Compose Services

```yaml
# Master
redis-master:
  image: redis:7-alpine
  container_name: odoo19_redis_master
  command: redis-server /usr/local/etc/redis/redis.conf
  volumes:
    - ./redis/redis-master.conf:/usr/local/etc/redis/redis.conf:ro
    - redis_master_data:/data

# Replicas (x2)
redis-replica-1:
  image: redis:7-alpine
  container_name: odoo19_redis_replica_1
  command: redis-server /usr/local/etc/redis/redis.conf
  depends_on: [redis-master]

redis-replica-2:
  image: redis:7-alpine
  container_name: odoo19_redis_replica_2
  command: redis-server /usr/local/etc/redis/redis.conf
  depends_on: [redis-master]

# Sentinels (x3)
redis-sentinel-1:
  image: redis:7-alpine
  container_name: odoo19_redis_sentinel_1
  command: redis-sentinel /usr/local/etc/redis/sentinel.conf
  depends_on: [redis-master, redis-replica-1, redis-replica-2]

redis-sentinel-2:
  image: redis:7-alpine
  container_name: odoo19_redis_sentinel_2
  command: redis-sentinel /usr/local/etc/redis/sentinel.conf
  depends_on: [redis-master, redis-replica-1, redis-replica-2]

redis-sentinel-3:
  image: redis:7-alpine
  container_name: odoo19_redis_sentinel_3
  command: redis-sentinel /usr/local/etc/redis/sentinel.conf
  depends_on: [redis-master, redis-replica-1, redis-replica-2]
```

### Configuration Files

**redis/redis-master.conf:**
- RDB + AOF persistence
- min-replicas-to-write = 1
- maxmemory = 512MB (LRU eviction)
- Password: odoo19_redis_pass

**redis/redis-replica.conf:**
- replicaof redis-master 6379
- replica-read-only = yes
- AOF persistence only (RDB from master)

**redis/sentinel.conf:**
- sentinel monitor mymaster redis-master 6379 2
- down-after-milliseconds = 5000 (5s)
- failover-timeout = 10000 (10s)
- parallel-syncs = 1

---

## Client Connection (AI Service)

### Sentinel-Aware Client

The AI service uses `redis-sentinel` library to connect via Sentinel:

```python
from redis.sentinel import Sentinel

# Sentinel hosts (all 3 for redundancy)
sentinel_hosts = [
    ("redis-sentinel-1", 26379),
    ("redis-sentinel-2", 26379),
    ("redis-sentinel-3", 26379),
]

# Initialize Sentinel
sentinel = Sentinel(
    sentinel_hosts,
    socket_timeout=0.5,
    password="odoo19_redis_pass",
    db=1
)

# Get master (read-write)
redis_master = sentinel.master_for(
    'mymaster',
    socket_timeout=5,
    password="odoo19_redis_pass",
    db=1
)

# Get slave (read-only)
redis_slave = sentinel.slave_for(
    'mymaster',
    socket_timeout=5,
    password="odoo19_redis_pass",
    db=1
)
```

### Environment Variables

```bash
# AI Service (docker-compose.yml)
REDIS_SENTINEL_ENABLED=true
REDIS_SENTINEL_HOSTS=redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379
REDIS_SENTINEL_MASTER_NAME=mymaster
REDIS_PASSWORD=odoo19_redis_pass
REDIS_DB=1

# Fallback (non-Sentinel mode)
REDIS_HOST=redis-master
REDIS_PORT=6379
```

---

## Deployment

### Initial Deployment

```bash
cd /Users/pedro/Documents/odoo19

# Stop old Redis (SPOF)
docker-compose stop redis
docker-compose rm -f redis

# Deploy Redis HA cluster
docker-compose up -d redis-master redis-replica-1 redis-replica-2
sleep 10

# Deploy Sentinels
docker-compose up -d redis-sentinel-1 redis-sentinel-2 redis-sentinel-3
sleep 10

# Restart AI service (will auto-discover master via Sentinel)
docker-compose restart ai-service
```

### Verification

```bash
# Check all containers running
docker-compose ps | grep redis

# Verify master
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster

# Verify replication
docker exec odoo19_redis_master redis-cli -a odoo19_redis_pass INFO replication

# Verify sentinels
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL masters
```

Expected output:
- 6 Redis containers: 1 master + 2 replicas + 3 sentinels
- Replication lag: <1s
- Sentinels: 3/3 monitoring master

---

## Failover Testing

### Automated Test

```bash
# Run failover test script
./test_redis_failover.sh
```

**Test Flow:**
1. Verify current master
2. Write test data to master
3. Stop master container (simulate failure)
4. Wait for Sentinel failover (<10s)
5. Verify new master promoted
6. Verify data integrity
7. Restart original master (becomes replica)
8. Verify final cluster state

### Manual Failover Test

```bash
# 1. Get current master
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster

# 2. Stop master
docker stop odoo19_redis_master

# 3. Watch Sentinel logs (failover in progress)
docker logs -f odoo19_redis_sentinel_1

# 4. Verify new master
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster

# 5. Restart original master (becomes replica)
docker start odoo19_redis_master

# 6. Verify cluster state
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL masters
```

---

## Monitoring

### Health Checks

All containers have health checks configured:

```yaml
healthcheck:
  test: ["CMD", "redis-cli", "-a", "odoo19_redis_pass", "ping"]
  interval: 10s
  timeout: 3s
  retries: 3
  start_period: 10s
```

### Key Metrics

```bash
# Master health
docker exec odoo19_redis_master redis-cli -a odoo19_redis_pass INFO replication

# Sentinel status
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL masters

# Replica lag
docker exec odoo19_redis_replica_1 redis-cli -a odoo19_redis_pass INFO replication

# Memory usage
docker exec odoo19_redis_master redis-cli -a odoo19_redis_pass INFO memory

# Slow queries
docker exec odoo19_redis_master redis-cli -a odoo19_redis_pass SLOWLOG GET 10
```

### Alerting Triggers

Recommended alerts (Prometheus/Grafana):

- Master down for >10s
- Replication lag >5s
- Memory usage >90%
- Sentinel quorum lost (< 2 sentinels)
- Replica disconnected >1 min
- Slow queries >100ms

---

## Backup & Recovery

### Backup Strategy

**Automated (RDB):**
- Snapshots every 15 min (if 1 key changed)
- Snapshots every 5 min (if 10 keys changed)
- Snapshots every 1 min (if 10,000 keys changed)
- Location: `/data/dump.rdb` (in redis_master_data volume)

**Automated (AOF):**
- Append-only log (every second fsync)
- Location: `/data/appendonly.aof`

### Manual Backup

```bash
# Trigger RDB snapshot
docker exec odoo19_redis_master redis-cli -a odoo19_redis_pass SAVE

# Backup RDB file
docker run --rm -v odoo19_redis_master_data:/data -v $(pwd):/backup alpine \
  tar czf /backup/redis_backup_$(date +%Y%m%d_%H%M%S).tar.gz /data/dump.rdb /data/appendonly.aof

# Verify backup
ls -lh redis_backup_*.tar.gz
```

### Recovery

```bash
# 1. Stop Redis cluster
docker-compose stop redis-master redis-replica-1 redis-replica-2

# 2. Restore RDB file to volume
docker run --rm -v odoo19_redis_master_data:/data -v $(pwd):/backup alpine \
  tar xzf /backup/redis_backup_YYYYMMDD_HHMMSS.tar.gz -C /

# 3. Start cluster
docker-compose up -d redis-master redis-replica-1 redis-replica-2
docker-compose up -d redis-sentinel-1 redis-sentinel-2 redis-sentinel-3

# 4. Verify data
docker exec odoo19_redis_master redis-cli -a odoo19_redis_pass DBSIZE
```

---

## Troubleshooting

### Master Not Responding

```bash
# Check logs
docker logs odoo19_redis_master

# Check health
docker exec odoo19_redis_master redis-cli -a odoo19_redis_pass PING

# Restart master
docker-compose restart redis-master
```

### Replica Not Syncing

```bash
# Check replica logs
docker logs odoo19_redis_replica_1

# Verify connectivity to master
docker exec odoo19_redis_replica_1 ping redis-master

# Force resync
docker exec odoo19_redis_replica_1 redis-cli -a odoo19_redis_pass REPLICAOF redis-master 6379
```

### Sentinel Not Detecting Failure

```bash
# Check Sentinel logs
docker logs odoo19_redis_sentinel_1

# Verify Sentinel can reach master
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL masters

# Reset Sentinel (last resort)
docker exec odoo19_redis_sentinel_1 redis-cli -p 26379 SENTINEL reset mymaster
```

### AI Service Cannot Connect

```bash
# Check AI service logs
docker logs odoo19_ai_service

# Verify Sentinel connectivity
docker exec odoo19_ai_service ping redis-sentinel-1

# Test Redis connection
docker exec odoo19_ai_service python3 -c "
from redis.sentinel import Sentinel
s = Sentinel([('redis-sentinel-1', 26379)], password='odoo19_redis_pass')
m = s.master_for('mymaster', password='odoo19_redis_pass')
print(m.ping())
"

# Restart AI service
docker-compose restart ai-service
```

---

## Performance Tuning

### Memory Optimization

```bash
# Check memory usage
docker exec odoo19_redis_master redis-cli -a odoo19_redis_pass INFO memory

# Adjust maxmemory (edit redis-master.conf)
maxmemory 1gb  # Increase from 512MB

# Restart master
docker-compose restart redis-master
```

### Replication Tuning

```bash
# Reduce replication lag (edit redis-master.conf)
repl-backlog-size 16mb  # Increase from default 1mb

# Adjust parallel syncs (edit sentinel.conf)
sentinel parallel-syncs mymaster 2  # Increase from 1
```

### Persistence Tuning

```bash
# Reduce RDB frequency (edit redis-master.conf)
save 3600 1     # Less aggressive
save 1800 10
save 300 10000

# AOF fsync policy (edit redis-master.conf)
appendfsync no  # Fastest (data loss risk)
appendfsync everysec  # Balance (default)
appendfsync always  # Safest (slow)
```

---

## Production Checklist

Before deploying to production:

- [ ] All 6 containers healthy
- [ ] Replication lag <1s
- [ ] Sentinels detecting master (3/3)
- [ ] Failover test passed (<10s)
- [ ] Data integrity verified
- [ ] Backups configured (RDB + AOF)
- [ ] Monitoring alerts configured
- [ ] AI service connecting via Sentinel
- [ ] Password changed from default
- [ ] Network isolation verified (no external ports)

---

## References

- **Redis Sentinel Documentation:** https://redis.io/topics/sentinel
- **Redis Replication:** https://redis.io/topics/replication
- **Redis Persistence:** https://redis.io/topics/persistence
- **redis-py Sentinel:** https://redis-py.readthedocs.io/en/stable/sentinel.html

---

**Migration Notes:**

**Before (Single Redis):**
- 1 container: `odoo19_redis`
- No replication, no failover
- SPOF (Single Point of Failure)
- Persistence: AOF only

**After (Redis HA):**
- 6 containers: 1M + 2R + 3S
- Automatic failover (<10s)
- Read scaling (2 replicas)
- Persistence: RDB + AOF
- Zero downtime architecture

**Breaking Changes:**
- Environment variables updated (REDIS_SENTINEL_* added)
- AI service code updated (redis_helper.py uses Sentinel)
- Odoo `depends_on` changed (`redis` → `redis-master`)

**Backwards Compatibility:**
- Set `REDIS_SENTINEL_ENABLED=false` to use direct connection
- Falls back to `redis-master:6379` if Sentinel disabled
