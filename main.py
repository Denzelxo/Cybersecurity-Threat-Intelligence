from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import uvicorn
from loguru import logger
from datetime import datetime, timedelta
import random
import json
from collections import defaultdict

app = FastAPI(
    title="Cybersecurity Threat Intelligence System",
    description="Autonomous Cybersecurity Threat Intelligence System",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simulated threat data
THREAT_TYPES = [
    "Malware", "Phishing", "DDoS", "Ransomware", 
    "SQL Injection", "XSS", "Zero-day", "APT"
]

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

# Threat intelligence data
THREAT_INTELLIGENCE = {
    "Malware": {
        "description": "Malicious software designed to harm or exploit systems",
        "indicators": ["Suspicious file hashes", "Known malware signatures", "Unusual system behavior"],
        "mitigation": ["Use antivirus software", "Keep systems updated", "Implement application whitelisting"],
        "related_threats": ["Ransomware", "APT"]
    },
    "Phishing": {
        "description": "Social engineering attacks to steal sensitive information",
        "indicators": ["Suspicious emails", "Fake login pages", "Urgent requests for information"],
        "mitigation": ["Email filtering", "User awareness training", "Multi-factor authentication"],
        "related_threats": ["Social Engineering", "Credential Theft"]
    },
    "DDoS": {
        "description": "Distributed Denial of Service attacks to overwhelm systems",
        "indicators": ["Unusual traffic patterns", "Multiple source IPs", "Service degradation"],
        "mitigation": ["DDoS protection services", "Traffic filtering", "Load balancing"],
        "related_threats": ["Botnet", "Network Flooding"]
    }
}

# Threat correlation patterns
THREAT_CORRELATIONS = {
    "Malware": {
        "Ransomware": 0.8,
        "APT": 0.6,
        "Phishing": 0.4
    },
    "Phishing": {
        "Credential Theft": 0.9,
        "Social Engineering": 0.7,
        "Malware": 0.4
    },
    "DDoS": {
        "Botnet": 0.9,
        "Network Flooding": 0.8,
        "APT": 0.3
    }
}

# Vulnerability database
VULNERABILITY_DB = {
    "CVE-2023-1234": {
        "name": "Remote Code Execution in Web Server",
        "severity": "Critical",
        "affected_versions": ["1.0.0", "1.1.0"],
        "fix_available": True,
        "cvss_score": 9.8
    },
    "CVE-2023-5678": {
        "name": "SQL Injection Vulnerability",
        "severity": "High",
        "affected_versions": ["2.0.0"],
        "fix_available": True,
        "cvss_score": 8.5
    }
}

class ThreatAnalysisRequest(BaseModel):
    threat_type: str
    context: Optional[Dict[str, Any]] = None

class VulnerabilityScanRequest(BaseModel):
    target_system: str
    scan_type: str = "full"

class BehavioralAnalysisRequest(BaseModel):
    user_id: str
    time_range: str = "24h"

def generate_threat_data():
    return {
        "timestamp": datetime.now().isoformat(),
        "threat_type": random.choice(THREAT_TYPES),
        "severity": random.choice(SEVERITY_LEVELS),
        "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "target_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "confidence_score": round(random.uniform(0.5, 1.0), 2)
    }

def analyze_threat_correlations(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze correlations between different threats"""
    correlations = defaultdict(list)
    for threat in threats:
        threat_type = threat["threat_type"]
        if threat_type in THREAT_CORRELATIONS:
            for related_threat, correlation in THREAT_CORRELATIONS[threat_type].items():
                if correlation > 0.5:  # Only show strong correlations
                    correlations[threat_type].append({
                        "related_threat": related_threat,
                        "correlation_score": correlation,
                        "confidence": round(random.uniform(0.7, 0.95), 2)
                    })
    return dict(correlations)

def predict_future_threats(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Predict potential future threats based on current patterns"""
    threat_counts = defaultdict(int)
    for threat in threats:
        threat_counts[threat["threat_type"]] += 1
    
    predictions = []
    for threat_type, count in threat_counts.items():
        if count >= 2:  # If we've seen this threat multiple times
            predictions.append({
                "threat_type": threat_type,
                "probability": round(min(0.5 + (count * 0.1), 0.9), 2),
                "expected_timeframe": f"{random.randint(1, 48)} hours",
                "confidence": round(random.uniform(0.6, 0.9), 2)
            })
    
    return {
        "predictions": predictions,
        "analysis_period": "24 hours",
        "confidence_threshold": 0.7
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Welcome to the Autonomous Cybersecurity Threat Intelligence System",
        "version": "1.0.0"
    }

@app.get("/api/v1/status")
async def get_status():
    """Get system status"""
    return {
        "status": "operational",
        "message": "Basic server is running"
    }

@app.get("/api/v1/threats/dashboard")
async def get_threat_dashboard():
    """Get real-time threat monitoring dashboard"""
    # Generate simulated threat data for the last 24 hours
    threats = []
    for _ in range(10):  # Generate 10 recent threats
        threat = generate_threat_data()
        threat["timestamp"] = (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat()
        threats.append(threat)
    
    # Calculate threat statistics
    threat_stats = {
        "total_threats": len(threats),
        "severity_distribution": {
            level: len([t for t in threats if t["severity"] == level])
            for level in SEVERITY_LEVELS
        },
        "threat_type_distribution": {
            threat_type: len([t for t in threats if t["threat_type"] == threat_type])
            for threat_type in THREAT_TYPES
        },
        "average_confidence": round(sum(t["confidence_score"] for t in threats) / len(threats), 2)
    }
    
    # Add threat correlations and predictions
    correlations = analyze_threat_correlations(threats)
    predictions = predict_future_threats(threats)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "threats": threats,
        "statistics": threat_stats,
        "correlations": correlations,
        "predictions": predictions,
        "recommendations": [
            "Implement network segmentation",
            "Update firewall rules",
            "Review access controls",
            "Monitor suspicious IP addresses"
        ]
    }

@app.post("/api/v1/threats/analyze")
async def analyze_threat(request: ThreatAnalysisRequest):
    """Get detailed threat intelligence analysis"""
    threat_type = request.threat_type
    if threat_type not in THREAT_INTELLIGENCE:
        raise HTTPException(status_code=404, detail=f"Threat type '{threat_type}' not found")
    
    # Get base threat intelligence
    threat_info = THREAT_INTELLIGENCE[threat_type]
    
    # Generate simulated recent incidents
    recent_incidents = []
    for _ in range(3):
        incident = {
            "timestamp": (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
            "severity": random.choice(SEVERITY_LEVELS),
            "source": f"IP: {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "status": random.choice(["Detected", "Blocked", "Investigation"])
        }
        recent_incidents.append(incident)
    
    # Generate risk assessment
    risk_assessment = {
        "current_risk_level": random.choice(SEVERITY_LEVELS),
        "trend": random.choice(["Increasing", "Stable", "Decreasing"]),
        "confidence": round(random.uniform(0.7, 0.95), 2)
    }
    
    return {
        "threat_type": threat_type,
        "analysis": {
            "description": threat_info["description"],
            "indicators": threat_info["indicators"],
            "mitigation": threat_info["mitigation"],
            "related_threats": threat_info["related_threats"]
        },
        "recent_incidents": recent_incidents,
        "risk_assessment": risk_assessment,
        "recommendations": [
            f"Implement {mitigation}" for mitigation in threat_info["mitigation"]
        ],
        "context_analysis": {
            "environment_impact": random.choice(["Low", "Medium", "High"]),
            "detection_capability": round(random.uniform(0.6, 0.9), 2),
            "response_time": f"{random.randint(1, 24)} hours"
        }
    }

@app.post("/api/v1/vulnerabilities/scan")
async def scan_vulnerabilities(request: VulnerabilityScanRequest):
    """Scan for vulnerabilities in the target system"""
    # Simulate vulnerability scan
    vulnerabilities = []
    for cve_id, vuln_info in VULNERABILITY_DB.items():
        if random.random() < 0.3:  # 30% chance of finding each vulnerability
            vulnerabilities.append({
                "cve_id": cve_id,
                **vuln_info,
                "detected_at": datetime.now().isoformat(),
                "affected_component": f"Component-{random.randint(1, 5)}",
                "recommended_action": "Update to latest version"
            })
    
    return {
        "scan_id": f"scan-{random.randint(1000, 9999)}",
        "target_system": request.target_system,
        "scan_type": request.scan_type,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": vulnerabilities,
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "critical_count": len([v for v in vulnerabilities if v["severity"] == "Critical"]),
            "high_count": len([v for v in vulnerabilities if v["severity"] == "High"]),
            "scan_duration": f"{random.randint(1, 10)} minutes"
        }
    }

@app.post("/api/v1/behavior/analyze")
async def analyze_behavior(request: BehavioralAnalysisRequest):
    """Analyze user and system behavior for anomalies"""
    # Simulate behavioral analysis
    anomalies = []
    for _ in range(random.randint(0, 3)):
        anomaly = {
            "timestamp": (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat(),
            "type": random.choice([
                "Unusual login time",
                "Multiple failed attempts",
                "Unusual data access pattern",
                "Suspicious file access"
            ]),
            "severity": random.choice(SEVERITY_LEVELS),
            "confidence": round(random.uniform(0.7, 0.95), 2),
            "details": {
                "location": f"IP: {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "device": random.choice(["Desktop", "Mobile", "Tablet"]),
                "browser": random.choice(["Chrome", "Firefox", "Safari"])
            }
        }
        anomalies.append(anomaly)
    
    return {
        "user_id": request.user_id,
        "time_range": request.time_range,
        "analysis_timestamp": datetime.now().isoformat(),
        "anomalies": anomalies,
        "risk_score": round(random.uniform(0, 1), 2),
        "behavioral_patterns": {
            "login_frequency": f"{random.randint(1, 10)} times per day",
            "usual_access_times": ["09:00-11:00", "14:00-16:00"],
            "common_actions": ["File access", "Email", "Database queries"]
        }
    }

@app.post("/api/v1/threats/automated-response")
async def automated_response(threat_type: str, background_tasks: BackgroundTasks):
    """Execute automated response to detected threats"""
    # Simulate automated response actions
    response_actions = []
    
    if threat_type == "Malware":
        response_actions = [
            "Isolating affected system",
            "Blocking malicious IPs",
            "Updating antivirus signatures",
            "Scanning for similar threats"
        ]
    elif threat_type == "DDoS":
        response_actions = [
            "Enabling DDoS protection",
            "Blocking attack sources",
            "Scaling up resources",
            "Implementing rate limiting"
        ]
    elif threat_type == "Phishing":
        response_actions = [
            "Blocking malicious domains",
            "Updating email filters",
            "Notifying affected users",
            "Enhancing spam protection"
        ]
    
    # Simulate response execution
    for action in response_actions:
        background_tasks.add_task(
            lambda: logger.info(f"Executing automated response: {action}")
        )
    
    return {
        "threat_type": threat_type,
        "response_timestamp": datetime.now().isoformat(),
        "actions_taken": response_actions,
        "status": "In Progress",
        "estimated_completion": f"{random.randint(1, 5)} minutes"
    }

@app.post("/api/v1/threats/share")
async def share_threat_intelligence(threat_data: Dict[str, Any]):
    """Share threat intelligence with other systems"""
    # Simulate threat intelligence sharing
    shared_data = {
        "threat_id": f"THREAT-{random.randint(1000, 9999)}",
        "timestamp": datetime.now().isoformat(),
        "shared_data": threat_data,
        "sharing_status": "Success",
        "recipients": [
            "Threat Intelligence Platform 1",
            "Security Operations Center",
            "Partner Organization"
        ]
    }
    
    return {
        "status": "success",
        "message": "Threat intelligence shared successfully",
        "shared_data": shared_data
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    ) 