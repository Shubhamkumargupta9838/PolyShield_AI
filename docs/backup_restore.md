# PolyShield AI — Backup, Restore & Disaster Recovery Procedure

## 1. Overview

This document defines the database backup, artifact volume snapshot, and disaster recovery procedures for **PolyShield AI**.

---

## 2. Data Classification & Backup Requirements

| Component | Storage Location | Data Type | Recommended Frequency | Backup Tool |
| :--- | :--- | :--- | :--- | :--- |
| **MongoDB Database** | `mongo_prod_data` volume | Scan records, report docs, XAI metadata | Daily (Automated) | `mongodump` / LVM Snapshot |
| **Analysis Artifacts** | `app_storage` volume | Extracted static/dynamic JSON reports | Daily (Automated) | `tar` / AWS S3 Sync |
| **ML Model Weights** | `ml/artifacts/` | Model checkpoints & scalers | Per release commit | Git LFS / S3 Bucket |
| **Redis Cache** | `redis_prod_data` volume | Ephemeral job state / broker queues | Ephemeral (No backup needed) | N/A |

---

## 3. MongoDB Backup Procedure

### Online Hot Backup (`mongodump`)
```bash
# Execute mongodump inside container
docker exec -t polyshield_prod_mongodb mongodump \
  --db polyshield_db \
  --archive=/data/db/backup_$(date +%Y%m%d_%H%M%S).archive \
  --gzip
```

### Off-host Transfer
```bash
docker cp polyshield_prod_mongodb:/data/db/backup_latest.archive /backups/mongodb/
```

---

## 4. MongoDB Restore Procedure

```bash
# Execute mongorestore from backup archive
docker exec -i polyshield_prod_mongodb mongorestore \
  --archive=/data/db/backup_latest.archive \
  --gzip \
  --drop
```

---

## 5. Artifact Volume Snapshot Procedure

```bash
# Archive app_storage volume
docker run --rm \
  -v polyshield_ai_app_storage:/volume \
  -v /backups/artifacts:/backup \
  alpine tar -czf /backup/app_storage_$(date +%Y%m%d).tar.gz -C /volume .
```

---

## 6. Disaster Recovery Verification

- **Recovery Time Objective (RTO)**: < 30 minutes
- **Recovery Point Objective (RPO)**: < 24 hours
- **Verification Rule**: Monthly restore drills must be performed in a separate staging environment using synthetic test datasets.
