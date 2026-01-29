# SpectrusGuard v3.0 - Advanced Threat Analytics & ML Detection

## 🧠 Overview

SpectrusGuard v3.0 introduces **User and Entity Behavior Analytics (UEBA)**, transforming the security plugin from a rule-based system to an intelligent, learning security platform.

## 🎯 What is UEBA?

**User and Entity Behavior Analytics (UEBA)** is a cybersecurity approach that uses machine learning and statistical analysis to detect anomalous behavior that deviates from normal patterns.

### The Problem

Traditional security systems (WAF, Geo-Block) can be bypassed:
- **WAF evasion**: Hackers use encoding tricks to bypass regex rules
- **VPN bypass**: Geo-Block doesn't block VPN users
- **Stealth attacks**: Low-and-slow attacks avoid detection

### The Solution: Behavior Analytics

**What hackers CAN'T hide**: Their behavior patterns.

#### Real-World Examples

| Scenario | Traditional Security | UEBA Detection |
|----------|---------------------|-----------------|
| **Bot attack** | Blocks known bot user-agents | Detects: 50 pages in 1 second (velocity anomaly) |
| **Account takeover** | Blocks brute force | Detects: Login at 3 AM from new device (time + device anomaly) |
| **Privilege escalation** | Blocks suspicious queries | Detects: Admin actions after normal working hours (behavior anomaly) |
| **Data exfiltration** | Blocks large uploads | Detects: Unusual download pattern (sequence anomaly) |

---

## 🏗️ Architecture

### Component Structure

```
includes/ueba/
├── class-sg-ueba-engine.php           # Main orchestrator
├── class-sg-metrics-collector.php    # Data collection
├── class-sg-behavior-profile.php     # Baseline management
├── class-sg-anomaly-detector.php    # Statistical detection
├── class-sg-risk-scorer.php         # Risk scoring
└── class-sg-response-engine.php      # Automated responses
```

### Data Flow

```
User Action
    ↓
Metrics Collection
    ↓
Baseline Comparison
    ↓
Anomaly Detection (Z-Score, IQR, Pattern)
    ↓
Risk Scoring (0-100)
    ↓
Response Execution (Log/Warn/Block)
```

---

## 📊 Metrics Collected

### Login Metrics
- Login frequency (per day)
- Login success rate
- Geographic location (country, city)
- Time of day (hour, day of week)
- Device/browser fingerprint
- IP reputation (Tor, VPN)
- Time since last login

### Request Metrics
- Request rate (per minute)
- Request patterns (sequential vs random)
- Resource types accessed
- Error rate (404, 403, 500)
- Inactivity periods

### User Metrics
- Administrative actions performed
- Content creation patterns
- Settings modifications
- Role-specific behavior

### IP Metrics
- Historical activity
- Multiple users from same IP
- Tor/VPN usage
- Bot behavior patterns

---

## 🔬 Detection Algorithms

### 1. Z-Score Anomaly Detection

**What it does**: Detects values that deviate significantly from the mean.

**Formula**:
```
Z-Score = (Value - Mean) / Standard Deviation
```

**Threshold**: Z-Score > 3.0 (99.7% confidence)

**Example**:
```php
// Normal: 2-5 logins per day (mean=3.5, std_dev=1.0)
// Anomaly: 20 logins today
// Z-Score = (20 - 3.5) / 1.0 = 16.5 → CRITICAL
```

### 2. IQR (Interquartile Range) Method

**What it does**: Detects outliers using quartiles.

**Formula**:
```
Lower Bound = Q1 - 1.5 * IQR
Upper Bound = Q3 + 1.5 * IQR
```

**Use Case**: Robust to extreme values, better than Z-Score for skewed data.

### 3. Moving Average Deviation

**What it does**: Compares current value to recent average.

**Use Case**: Detect sudden changes in behavior patterns.

**Example**:
```php
// Recent 10 requests: 2, 2, 3, 2, 2, 3, 2, 2, 3, 2 (mean=2.3)
// Current: 20 requests
// Deviation = |20 - 2.3| / 2.3 = 770% → Anomaly
```

### 4. Sequential Pattern Analysis

**What it does**: Detects unusual navigation sequences.

**Example**:
```php
// Normal: Dashboard → Posts → New Post → Publish
// Anomaly: Dashboard → Settings → Plugins → Upload → File Edit
```

---

## 🎯 Risk Scoring

### Risk Score Formula

```
Risk Score = Σ (Anomaly Weight × Severity Multiplier)
```

### Risk Categories

| Score Range | Risk Level | Color | Action |
|-------------|-----------|--------|--------|
| 0-19 | LOW | 🟢 Green | Log only |
| 20-49 | MEDIUM | 🟡 Yellow | Warning to user |
| 50-79 | HIGH | 🟠 Orange | Require 2FA |
| 80-100 | CRITICAL | 🔴 Red | Block + Notify Admin |

### Risk Weights

| Anomaly Type | Weight (Max Points) |
|--------------|-------------------|
| Geo Anomaly | 25 |
| Login Frequency | 20 |
| Request Rate | 15 |
| Time Anomaly | 15 |
| IP Reputation | 15 |
| Device Anomaly | 10 |

### Severity Multipliers

- **LOW**: 0.3 (30% of max points)
- **MEDIUM**: 0.6 (60% of max points)
- **HIGH**: 0.9 (90% of max points)
- **CRITICAL**: 1.0 (100% of max points)

---

## 🚨 Automated Responses

### LOW Risk (0-19)
- **Action**: Log event
- **User Impact**: None
- **Admin Notification**: No

### MEDIUM Risk (20-49)
- **Action**: Show warning banner
- **User Impact**: Informative notice
- **Admin Notification**: No

### HIGH Risk (50-79)
- **Action**: Require additional 2FA
- **User Impact**: Extra verification step
- **Admin Notification**: Yes (email)

### CRITICAL Risk (80-100)
- **Action**: Block IP + Logout user
- **User Impact**: Access denied
- **Admin Notification**: Yes (urgent email)

---

## 📈 Dashboard Features

### Real-Time Analytics

1. **Risk Score Overview**
   - Distribution: LOW/MEDIUM/HIGH/CRITICAL
   - Color-coded cards with percentages

2. **Activity Chart**
   - Last 24 hours timeline
   - Security events vs anomalies
   - Interactive Chart.js visualization

3. **Top Risky Users**
   - User details (username, email)
   - Current risk score (0-100)
   - Risk level badge
   - Last activity timestamp
   - Anomaly count

4. **Top Risky IPs**
   - IP address
   - Failed login count
   - Anomaly count
   - Last seen timestamp
   - Block IP button

5. **Recent Anomalies**
   - Anomaly type
   - Severity level
   - Description
   - Affected user
   - Source IP
   - Time ago

---

## 🔧 Configuration

### Settings

```php
$spectrus_shield_settings = array(
    // UEBA Settings
    'ueba_enabled' => true,
    'baseline_min_days' => 7,
    'risk_threshold_high' => 50,
    'risk_threshold_critical' => 80,

    // Anomaly Detection Thresholds
    'z_score_threshold' => 3.0,
    'request_rate_threshold' => 100, // req/min

    // Risk Weights (configurable)
    'risk_weights' => array(
        'login_frequency' => 20,
        'time_anomaly' => 15,
        'geo_anomaly' => 25,
        'device_anomaly' => 10,
        'request_rate_anomaly' => 15,
        'ip_reputation' => 15,
    ),
);
```

### REST API Endpoints

#### Get User Risk Score
```
GET /wp-json/spectrus-guard/v1/ueba/risk-score/{user_id}
```

**Response**:
```json
{
  "user_id": 1,
  "risk_score": 35,
  "risk_level": "MEDIUM"
}
```

#### Get User Baseline
```
GET /wp-json/spectrus-guard/v1/ueba/baseline/{user_id}
```

**Response**:
```json
{
  "status": "ready",
  "days_of_data": 15,
  "login_frequency": {
    "mean": 3.5,
    "std_dev": 1.2,
    "median": 3.0
  },
  "login_hours": [8, 9, 10, 14, 15, 16],
  "login_countries": ["US", "CA"]
}
```

#### Get User Anomalies
```
GET /wp-json/spectrus-guard/v1/ueba/anomalies/{user_id}
```

**Response**:
```json
{
  "user_id": 1,
  "anomalies": [
    {
      "type": "time_anomaly",
      "severity": "MEDIUM",
      "description": "Login at unusual time: 02:00"
    }
  ]
}
```

---

## 🗄️ Database Schema

### `wp_spectrus_ueba_metrics` Table

| Column | Type | Description |
|--------|------|-------------|
| `id` | BIGINT(20) | Primary key |
| `event_type` | VARCHAR(50) | Event type (login, request, etc.) |
| `user_id` | BIGINT(20) | User ID (nullable for failed logins) |
| `user_login` | VARCHAR(100) | Username |
| `user_role` | VARCHAR(50) | User role |
| `ip` | VARCHAR(45) | IP address (IPv4/IPv6) |
| `user_agent` | TEXT | User agent string |
| `device_fingerprint` | VARCHAR(32) | Device/browser fingerprint |
| `country` | VARCHAR(2) | ISO country code |
| `is_tor` | TINYINT(1) | Is Tor exit node |
| `is_vpn` | TINYINT(1) | Is VPN/datacenter |
| `success` | TINYINT(1) | Event success status |
| `timestamp` | DATETIME | Event timestamp |
| `hour` | TINYINT(2) | Hour of day (0-23) |
| `day_of_week` | TINYINT(1) | Day of week (0-6) |
| `action` | VARCHAR(100) | Action performed |
| `request_uri` | TEXT | Request URI |
| `request_method` | VARCHAR(10) | Request method |

**Indexes**:
- `event_type`
- `user_id`
- `ip`
- `timestamp`
- `event_user` (composite: event_type, user_id, timestamp)

---

## 🔒 Security Features

### 1. Zero-Trust Approach
- No input is trusted without validation
- Every metric is sanitized before storage
- IP spoofing protection with trusted proxies

### 2. Fail-Open Design
- If baseline is insufficient, allow access
- Prevents lockout scenarios
- Logs warnings for manual review

### 3. Adaptive Learning
- Baselines update continuously
- Exponential decay for old data
- Seasonality awareness (weekdays vs weekends)

### 4. Privacy Preserved
- No personally identifiable data stored
- Hashed device fingerprints
- Configurable data retention (default: 90 days)

---

## 🚀 Performance Optimization

### Caching Strategy

```php
// Baseline caching (1 hour)
$baseline = wp_cache_get('ueba_baseline_' . $user_id, 'spectrus');

if ($baseline === false) {
    $baseline = $this->behavior_profile->get_baseline($user_id);
    wp_cache_set('ueba_baseline_' . $user_id, $baseline, 'spectrus', 3600);
}
```

### Database Optimization
- Composite indexes for common queries
- Limit query results with proper pagination
- Use `COUNT(*)` instead of fetching all rows

### Lazy Loading
- Only load UEBA engine when needed
- Skip collection for non-admin users
- Conditional anomaly detection based on risk level

---

## 📚 API Documentation

### Public Methods

#### `SG_UEBA_Engine`

```php
// Initialize UEBA
$ueba = new SG_UEBA_Engine($logger);

// Get components
$metrics_collector = $ueba->get_metrics_collector();
$behavior_profile = $ueba->get_behavior_profile();
$anomaly_detector = $ueba->get_anomaly_detector();
$risk_scorer = $ueba->get_risk_scorer();
$response_engine = $ueba->get_response_engine();
```

#### `SG_Metrics_Collector`

```php
// Collect login metrics
$metrics = $metrics_collector->collect_login_metrics($user);

// Get request rate
$rate = $metrics_collector->get_request_rate($user_id, 5);

// Get login history
$history = $metrics_collector->get_login_history($user_id, 10);
```

#### `SG_Behavior_Profile`

```php
// Get baseline
$baseline = $behavior_profile->get_baseline($user_id);

// Update baseline
$behavior_profile->update_baseline($user_id, $metrics);

// Get IP baseline
$ip_baseline = $behavior_profile->get_ip_baseline($ip);
```

#### `SG_Anomaly_Detector`

```php
// Detect anomalies
$anomalies = $anomaly_detector->detect_anomalies($metrics, $baseline);

// Detect outliers using IQR
$outliers = $anomaly_detector->detect_outliers_iqr($data);

// Calculate Z-Score
$z_score = $anomaly_detector->calculate_z_score($value, $mean, $std_dev);
```

#### `SG_Risk_Scorer`

```php
// Calculate risk score
$score = $risk_scorer->calculate_risk_score($user_id, $metrics, $baseline, $anomalies);

// Get risk level
$level = $risk_scorer->get_risk_level($score); // LOW/MEDIUM/HIGH/CRITICAL

// Get risk details
$details = $risk_scorer->get_risk_level_details($level);
```

#### `SG_Response_Engine`

```php
// Execute response
$response_engine->execute_response($risk_score, $risk_level, $context);

// Update actions
$response_engine->update_actions($new_actions);
```

---

## 🎓 Use Cases

### 1. Detecting Account Takeover

**Scenario**: Hacker gains user password but behaves differently.

**UEBA Detection**:
1. Login from unusual country (Geo anomaly: +25 points)
2. Login at unusual time (Time anomaly: +15 points)
3. New device fingerprint (Device anomaly: +10 points)

**Total Score**: 50/100 (HIGH RISK)

**Response**: Require additional 2FA + Notify admin

---

### 2. Detecting Bot Activity

**Scenario**: Bot scans for vulnerabilities.

**UEBA Detection**:
1. 100+ pages in 1 minute (Request rate anomaly: +15 points)
2. Sequential URL enumeration (Pattern anomaly: +10 points)

**Total Score**: 25/100 (MEDIUM RISK)

**Response**: Show warning + Log event

---

### 3. Detecting Insider Threat

**Scenario**: Disgruntled employee accesses sensitive data after hours.

**UEBA Detection**:
1. Admin actions at 11 PM (Time anomaly: +15 points)
2. Unusual content downloads (Pattern anomaly: +10 points)
3. Settings modifications (Action anomaly: +15 points)

**Total Score**: 40/100 (MEDIUM RISK → escalating)

**Response**: Require 2FA + Notify admin

---

## 🔄 Future Enhancements

### v3.1 Planned Features
- Machine learning clustering (K-Means for user groups)
- Predictive threat scoring (anticipate attacks)
- Behavioral biometrics (typing patterns)
- Real-time alerting (WebSocket/Server-Sent Events)

### v3.2 Planned Features
- Integration with SIEM platforms (Splunk, ELK)
- Threat intelligence feeds (AbuseIPDB, VirusTotal)
- Automated incident response (SOAR integration)
- Custom anomaly rules engine

---

## 📞 Support & Contributing

For bug reports, feature requests, or contributions, please visit:
- GitHub: https://github.com/carlosindriago/SpectrusGuard
- Documentation: https://docs.spectrusguard.com
- Support Email: support@spectrusguard.com

---

## 📄 License

GPL v2 or later

---

**SpectrusGuard v3.0 - Advanced Threat Analytics & ML Detection**

*Protecting WordPress sites with intelligent, adaptive security since 2024*
