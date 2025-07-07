#!/usr/bin/env python3
"""
Enhanced DLP v2.0 Core Engine
Advanced policy engine with ML, behavioral analytics, and zero-trust architecture
"""

import asyncio
import hashlib
import json
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import aioredis
import motor.motor_asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Enhanced Data Structures
class RiskLevel(Enum):
    """Risk scoring levels"""
    CRITICAL = 100
    HIGH = 75
    MEDIUM = 50
    LOW = 25
    MINIMAL = 10

class DataCategory(Enum):
    """Enhanced data classification categories"""
    PII = "personally_identifiable_information"
    PHI = "protected_health_information"
    PCI = "payment_card_information"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNKNOWN = "unknown"

class ActionType(Enum):
    """Enhanced action types"""
    ALLOW = auto()
    BLOCK = auto()
    ENCRYPT = auto()
    REDACT = auto()
    WATERMARK = auto()
    QUARANTINE = auto()
    ALERT = auto()
    LOG = auto()
    TOKENIZE = auto()
    DLP_SCAN = auto()
    USER_PROMPT = auto()
    ADAPTIVE_RESPONSE = auto()

@dataclass
class DataContext:
    """Enhanced context for data evaluation"""
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    user_id: str
    device_id: str
    location: Dict[str, Any]
    timestamp: float
    process_name: str
    process_id: int
    file_path: Optional[str] = None
    url: Optional[str] = None
    email_recipient: Optional[str] = None
    container_id: Optional[str] = None
    cloud_provider: Optional[str] = None
    risk_score: float = 0.0
    trust_score: float = 100.0
    behavioral_score: float = 0.0
    threat_indicators: List[str] = field(default_factory=list)
    
@dataclass
class MLPrediction:
    """Machine learning prediction result"""
    category: DataCategory
    confidence: float
    sub_categories: List[str]
    entities: List[Dict[str, Any]]  # Named entities extracted
    explanation: str
    model_version: str

@dataclass
class BehavioralProfile:
    """User/device behavioral profile"""
    entity_id: str
    entity_type: str  # user, device, application
    normal_patterns: Dict[str, Any]
    anomaly_scores: deque  # Rolling window of scores
    risk_events: List[Dict[str, Any]]
    last_updated: float
    baseline_established: bool
    
    def calculate_anomaly_score(self, current_behavior: Dict[str, Any]) -> float:
        """Calculate anomaly score based on baseline"""
        if not self.baseline_established:
            return 0.0
            
        score = 0.0
        # Compare current behavior with baseline
        for metric, baseline_value in self.normal_patterns.items():
            if metric in current_behavior:
                current_value = current_behavior[metric]
                if isinstance(baseline_value, (int, float)):
                    # Numerical comparison
                    deviation = abs(current_value - baseline_value) / (baseline_value + 1)
                    score += min(deviation * 10, 100)
                elif isinstance(baseline_value, list):
                    # Categorical comparison
                    if current_value not in baseline_value:
                        score += 20
                        
        return min(score, 100)


# Enhanced Core Engine
class EnhancedDLPEngine:
    """Enhanced DLP Engine with ML and advanced features"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ml_models = {}
        self.behavioral_profiles = {}
        self.threat_intelligence = ThreatIntelligenceService()
        self.zero_trust_evaluator = ZeroTrustEvaluator()
        self.data_classifier = DataClassifier()
        self.encryption_service = EncryptionService()
        self.forensics_collector = ForensicsCollector()
        self.redis_client = None
        self.mongo_client = None
        self.executor = ThreadPoolExecutor(max_workers=config.get('workers', 10))
        
    async def initialize(self):
        """Initialize all services"""
        # Connect to Redis for caching
        self.redis_client = await aioredis.create_redis_pool(
            self.config['redis_url'],
            encoding='utf-8'
        )
        
        # Connect to MongoDB for analytics
        self.mongo_client = motor.motor_asyncio.AsyncIOMotorClient(
            self.config['mongo_url']
        )
        self.db = self.mongo_client.dlp_analytics
        
        # Load ML models
        await self._load_ml_models()
        
        # Initialize threat intelligence feeds
        await self.threat_intelligence.initialize()
        
    async def evaluate_data(self, 
                          data: bytes, 
                          context: DataContext,
                          policies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Enhanced data evaluation with ML, behavioral analysis, and zero-trust
        """
        start_time = time.time()
        
        # 1. Data Classification
        classification = await self.data_classifier.classify(data, context)
        
        # 2. ML-based Detection
        ml_predictions = await self._run_ml_detection(data, classification)
        
        # 3. Behavioral Analysis
        behavioral_score = await self._analyze_behavior(context, classification)
        context.behavioral_score = behavioral_score
        
        # 4. Threat Intelligence Check
        threat_indicators = await self.threat_intelligence.check(context, data)
        context.threat_indicators = threat_indicators
        
        # 5. Zero-Trust Evaluation
        trust_score = await self.zero_trust_evaluator.evaluate(context)
        context.trust_score = trust_score
        
        # 6. Calculate Risk Score
        risk_score = self._calculate_risk_score(
            classification, ml_predictions, behavioral_score, 
            threat_indicators, trust_score
        )
        context.risk_score = risk_score
        
        # 7. Policy Evaluation with Context
        policy_results = await self._evaluate_policies(
            data, context, policies, classification, ml_predictions
        )
        
        # 8. Determine Actions
        actions = self._determine_actions(
            policy_results, risk_score, trust_score, context
        )
        
        # 9. Collect Forensics if needed
        if risk_score >= RiskLevel.HIGH.value:
            await self.forensics_collector.collect(
                data, context, classification, policy_results
            )
        
        # 10. Update Analytics
        await self._update_analytics(context, classification, actions)
        
        evaluation_time = time.time() - start_time
        
        return {
            'classification': classification,
            'ml_predictions': ml_predictions,
            'behavioral_score': behavioral_score,
            'trust_score': trust_score,
            'risk_score': risk_score,
            'threat_indicators': threat_indicators,
            'policy_matches': policy_results,
            'actions': actions,
            'evaluation_time': evaluation_time,
            'context': context
        }
    
    async def _run_ml_detection(self, 
                              data: bytes, 
                              classification: Dict[str, Any]) -> List[MLPrediction]:
        """Run ML models for advanced detection"""
        predictions = []
        
        # Convert data to features
        features = await self._extract_features(data, classification)
        
        # Run each specialized model
        for model_name, model in self.ml_models.items():
            if self._should_run_model(model_name, classification):
                prediction = await self._run_model_async(model, features)
                predictions.append(prediction)
                
        return predictions
    
    async def _analyze_behavior(self, 
                              context: DataContext, 
                              classification: Dict[str, Any]) -> float:
        """Analyze behavioral patterns"""
        # Get or create profile
        profile = await self._get_behavioral_profile(context)
        
        # Extract current behavior metrics
        current_behavior = {
            'data_category': classification['category'],
            'data_volume': classification.get('size', 0),
            'destination': context.destination_ip,
            'time_of_day': datetime.fromtimestamp(context.timestamp).hour,
            'day_of_week': datetime.fromtimestamp(context.timestamp).weekday(),
            'protocol': context.protocol,
            'risk_indicators': len(context.threat_indicators)
        }
        
        # Calculate anomaly score
        anomaly_score = profile.calculate_anomaly_score(current_behavior)
        
        # Update profile
        profile.anomaly_scores.append(anomaly_score)
        if len(profile.anomaly_scores) > 1000:
            profile.anomaly_scores.popleft()
            
        # Update baseline if needed
        if not profile.baseline_established and len(profile.anomaly_scores) > 100:
            await self._establish_baseline(profile)
            
        # Save profile
        await self._save_behavioral_profile(profile)
        
        return anomaly_score
    
    def _calculate_risk_score(self,
                            classification: Dict[str, Any],
                            ml_predictions: List[MLPrediction],
                            behavioral_score: float,
                            threat_indicators: List[str],
                            trust_score: float) -> float:
        """Calculate comprehensive risk score"""
        risk_score = 0.0
        
        # Data sensitivity factor
        sensitivity_scores = {
            DataCategory.PCI: 30,
            DataCategory.PHI: 30,
            DataCategory.PII: 25,
            DataCategory.INTELLECTUAL_PROPERTY: 25,
            DataCategory.CONFIDENTIAL: 20,
            DataCategory.INTERNAL: 10,
            DataCategory.PUBLIC: 0
        }
        
        data_category = DataCategory(classification['category'])
        risk_score += sensitivity_scores.get(data_category, 15)
        
        # ML confidence factor
        if ml_predictions:
            max_confidence = max(p.confidence for p in ml_predictions)
            risk_score += max_confidence * 20
            
        # Behavioral anomaly factor
        risk_score += (behavioral_score / 100) * 20
        
        # Threat intelligence factor
        risk_score += min(len(threat_indicators) * 10, 20)
        
        # Zero-trust factor (inverse relationship)
        risk_score += (100 - trust_score) / 10
        
        return min(risk_score, 100)
    
    def _determine_actions(self,
                         policy_results: List[Dict[str, Any]],
                         risk_score: float,
                         trust_score: float,
                         context: DataContext) -> List[ActionType]:
        """Determine actions based on comprehensive evaluation"""
        actions = []
        
        # Policy-based actions
        for result in policy_results:
            if result['matched']:
                actions.extend(result['actions'])
                
        # Risk-based adaptive actions
        if risk_score >= RiskLevel.CRITICAL.value:
            actions.extend([ActionType.BLOCK, ActionType.ALERT, ActionType.DLP_SCAN])
        elif risk_score >= RiskLevel.HIGH.value:
            actions.extend([ActionType.ENCRYPT, ActionType.ALERT, ActionType.LOG])
        elif risk_score >= RiskLevel.MEDIUM.value:
            actions.extend([ActionType.WATERMARK, ActionType.LOG])
            
        # Trust-based actions
        if trust_score < 30:
            actions.append(ActionType.USER_PROMPT)
            if ActionType.ALLOW in actions:
                actions.remove(ActionType.ALLOW)
                
        # Deduplicate and prioritize
        actions = list(set(actions))
        return self._prioritize_actions(actions)
    
    def _prioritize_actions(self, actions: List[ActionType]) -> List[ActionType]:
        """Prioritize actions by severity"""
        priority_order = [
            ActionType.BLOCK,
            ActionType.QUARANTINE,
            ActionType.USER_PROMPT,
            ActionType.ENCRYPT,
            ActionType.REDACT,
            ActionType.TOKENIZE,
            ActionType.WATERMARK,
            ActionType.DLP_SCAN,
            ActionType.ALERT,
            ActionType.LOG,
            ActionType.ALLOW
        ]
        
        return sorted(actions, key=lambda x: priority_order.index(x))


# Supporting Services
class DataClassifier:
    """Advanced data classification service"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
        self.ml_classifier = None
        
    async def classify(self, data: bytes, context: DataContext) -> Dict[str, Any]:
        """Classify data using patterns and ML"""
        text_data = self._safe_decode(data)
        
        # Pattern-based classification
        pattern_matches = self._match_patterns(text_data)
        
        # ML-based classification
        ml_category = None
        if self.ml_classifier:
            ml_category = await self._ml_classify(text_data)
            
        # Determine final category
        category = self._determine_category(pattern_matches, ml_category)
        
        # Extract metadata
        metadata = self._extract_metadata(data, text_data)
        
        return {
            'category': category.value,
            'confidence': self._calculate_confidence(pattern_matches, ml_category),
            'pattern_matches': pattern_matches,
            'ml_classification': ml_category,
            'metadata': metadata,
            'size': len(data),
            'entropy': self._calculate_entropy(data)
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
            
        frequencies = defaultdict(int)
        for byte in data:
            frequencies[byte] += 1
            
        entropy = 0.0
        data_len = len(data)
        
        for freq in frequencies.values():
            if freq > 0:
                prob = freq / data_len
                entropy -= prob * np.log2(prob)
                
        return entropy


class ThreatIntelligenceService:
    """Threat intelligence integration"""
    
    def __init__(self):
        self.threat_feeds = []
        self.indicators = {
            'ip_addresses': set(),
            'domains': set(),
            'file_hashes': set(),
            'patterns': []
        }
        
    async def initialize(self):
        """Load threat intelligence feeds"""
        # Load from various sources
        await self._load_commercial_feeds()
        await self._load_open_source_feeds()
        await self._load_custom_indicators()
        
    async def check(self, context: DataContext, data: bytes) -> List[str]:
        """Check for threat indicators"""
        indicators_found = []
        
        # Check IPs
        if context.destination_ip in self.indicators['ip_addresses']:
            indicators_found.append(f"suspicious_ip:{context.destination_ip}")
            
        # Check file hash
        file_hash = hashlib.sha256(data).hexdigest()
        if file_hash in self.indicators['file_hashes']:
            indicators_found.append(f"malicious_file:{file_hash}")
            
        # Check patterns
        text_data = data.decode('utf-8', errors='ignore')
        for pattern in self.indicators['patterns']:
            if pattern['regex'].search(text_data):
                indicators_found.append(f"threat_pattern:{pattern['name']}")
                
        return indicators_found


class ZeroTrustEvaluator:
    """Zero-trust security evaluation"""
    
    def __init__(self):
        self.trust_factors = {
            'device_compliance': 20,
            'user_authentication': 20,
            'network_location': 15,
            'time_based_access': 10,
            'behavioral_consistency': 15,
            'patch_level': 10,
            'encryption_status': 10
        }
        
    async def evaluate(self, context: DataContext) -> float:
        """Evaluate trust score based on zero-trust principles"""
        trust_score = 0.0
        
        # Device compliance check
        device_compliance = await self._check_device_compliance(context.device_id)
        trust_score += device_compliance * self.trust_factors['device_compliance']
        
        # User authentication strength
        auth_strength = await self._check_auth_strength(context.user_id)
        trust_score += auth_strength * self.trust_factors['user_authentication']
        
        # Network location trust
        network_trust = self._evaluate_network_location(context.location)
        trust_score += network_trust * self.trust_factors['network_location']
        
        # Time-based access control
        time_trust = self._evaluate_time_access(context.timestamp, context.user_id)
        trust_score += time_trust * self.trust_factors['time_based_access']
        
        # Behavioral consistency
        behavioral_trust = await self._check_behavioral_consistency(context)
        trust_score += behavioral_trust * self.trust_factors['behavioral_consistency']
        
        return min(trust_score, 100)
    
    async def _check_device_compliance(self, device_id: str) -> float:
        """Check device compliance status"""
        # Check MDM compliance, patch level, security software
        # This would integrate with MDM/UEM solutions
        return 0.8  # Placeholder
    
    def _evaluate_network_location(self, location: Dict[str, Any]) -> float:
        """Evaluate network location trust"""
        if location.get('type') == 'corporate':
            return 1.0
        elif location.get('type') == 'vpn':
            return 0.8
        elif location.get('country') in self._get_trusted_countries():
            return 0.6
        else:
            return 0.3


class EncryptionService:
    """Advanced encryption service with hardware acceleration"""
    
    def __init__(self):
        self.key_manager = KeyManager()
        self.hardware_crypto = HardwareCryptoAccelerator()
        
    async def encrypt_data(self, 
                          data: bytes, 
                          context: DataContext,
                          encryption_policy: Dict[str, Any]) -> bytes:
        """Encrypt data with policy-based encryption"""
        # Get encryption key based on classification
        key = await self.key_manager.get_key(context, encryption_policy)
        
        # Use hardware acceleration if available
        if self.hardware_crypto.is_available():
            return await self.hardware_crypto.encrypt(data, key)
        else:
            # Software encryption fallback
            fernet = Fernet(key)
            return fernet.encrypt(data)
    
    async def tokenize_data(self, 
                          data: str, 
                          token_type: str) -> Tuple[str, str]:
        """Tokenize sensitive data"""
        # Generate unique token
        token = self._generate_token(data, token_type)
        
        # Store mapping securely
        await self._store_token_mapping(token, data)
        
        return token, f"[{token_type}:{token}]"
    
    def _generate_token(self, data: str, token_type: str) -> str:
        """Generate format-preserving token"""
        # Implement format-preserving encryption
        if token_type == 'credit_card':
            # Preserve first 6 and last 4 digits
            return f"{data[:6]}{'*' * 6}{data[-4:]}"
        elif token_type == 'ssn':
            # Preserve last 4 digits
            return f"***-**-{data[-4:]}"
        else:
            # Generic tokenization
            return hashlib.sha256(data.encode()).hexdigest()[:16]


class ForensicsCollector:
    """Advanced forensics and incident response"""
    
    def __init__(self):
        self.evidence_store = EvidenceStore()
        self.timeline_builder = TimelineBuilder()
        
    async def collect(self,
                     data: bytes,
                     context: DataContext,
                     classification: Dict[str, Any],
                     policy_results: List[Dict[str, Any]]):
        """Collect forensic evidence"""
        incident_id = self._generate_incident_id(context)
        
        # Collect evidence
        evidence = {
            'incident_id': incident_id,
            'timestamp': context.timestamp,
            'data_sample': self._sanitize_data_sample(data),
            'context': context.__dict__,
            'classification': classification,
            'policy_violations': policy_results,
            'network_capture': await self._capture_network_context(context),
            'process_tree': await self._get_process_tree(context.process_id),
            'file_metadata': await self._get_file_metadata(context.file_path)
        }
        
        # Store evidence
        await self.evidence_store.store(evidence)
        
        # Build timeline
        await self.timeline_builder.add_event(incident_id, evidence)
        
        # Trigger automated response if needed
        if self._requires_immediate_response(classification, context.risk_score):
            await self._trigger_incident_response(incident_id, evidence)
    
    def _sanitize_data_sample(self, data: bytes) -> str:
        """Sanitize data for storage"""
        # Redact sensitive information but preserve structure
        text = data.decode('utf-8', errors='ignore')
        
        # Redact patterns
        patterns = [
            (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN-REDACTED]'),
            (r'\b\d{13,16}\b', '[CC-REDACTED]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL-REDACTED]')
        ]
        
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text)
            
        return text[:1000]  # Limit sample size


# Hardware Acceleration Support
class HardwareCryptoAccelerator:
    """Hardware crypto acceleration support"""
    
    def __init__(self):
        self.intel_qat = self._check_intel_qat()
        self.aes_ni = self._check_aes_ni()
        self.gpu_crypto = self._check_gpu_crypto()
        
    def is_available(self) -> bool:
        """Check if hardware acceleration is available"""
        return any([self.intel_qat, self.aes_ni, self.gpu_crypto])
    
    async def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using hardware acceleration"""
        if self.intel_qat:
            return await self._qat_encrypt(data, key)
        elif self.aes_ni:
            return await self._aesni_encrypt(data, key)
        elif self.gpu_crypto:
            return await self._gpu_encrypt(data, key)
        else:
            raise RuntimeError("No hardware acceleration available")
    
    def _check_intel_qat(self) -> bool:
        """Check for Intel QuickAssist Technology"""
        try:
            import pyqat
            return pyqat.is_available()
        except:
            return False
    
    def _check_aes_ni(self) -> bool:
        """Check for AES-NI instructions"""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                return 'aes' in cpuinfo
        except:
            return False
    
    def _check_gpu_crypto(self) -> bool:
        """Check for GPU crypto support"""
        try:
            import pycuda.driver as cuda
            cuda.init()
            return cuda.Device.count() > 0
        except:
            return False


# ML Model Management
class MLModelManager:
    """Manage ML models for DLP"""
    
    def __init__(self):
        self.models = {}
        self.model_versions = {}
        self.performance_metrics = defaultdict(dict)
        
    async def load_model(self, model_name: str, model_path: str):
        """Load ML model with versioning"""
        # Load model based on framework
        if model_path.endswith('.onnx'):
            model = await self._load_onnx_model(model_path)
        elif model_path.endswith('.pb'):
            model = await self._load_tensorflow_model(model_path)
        elif model_path.endswith('.pt'):
            model = await self._load_pytorch_model(model_path)
        else:
            raise ValueError(f"Unsupported model format: {model_path}")
            
        self.models[model_name] = model
        self.model_versions[model_name] = self._extract_version(model_path)
        
    async def predict(self, model_name: str, features: np.ndarray) -> MLPrediction:
        """Make prediction with performance tracking"""
        start_time = time.time()
        
        model = self.models[model_name]
        prediction = await model.predict(features)
        
        # Track performance
        inference_time = time.time() - start_time
        self.performance_metrics[model_name]['inference_times'].append(inference_time)
        
        return self._format_prediction(prediction, model_name)
    
    async def update_model(self, model_name: str, new_model_path: str):
        """Hot-swap model without downtime"""
        # Load new model
        new_model = await self.load_model(f"{model_name}_new", new_model_path)
        
        # A/B test if configured
        if self._should_ab_test(model_name):
            await self._run_ab_test(model_name, new_model)
            
        # Swap models
        old_model = self.models[model_name]
        self.models[model_name] = new_model
        
        # Cleanup old model
        del old_model


# Data Discovery and Classification
class DataDiscoveryService:
    """Discover and classify data across the organization"""
    
    def __init__(self):
        self.scanners = {
            'filesystem': FileSystemScanner(),
            'database': DatabaseScanner(),
            'cloud': CloudStorageScanner(),
            'email': EmailScanner(),
            'endpoint': EndpointScanner()
        }
        self.classification_engine = DataClassifier()
        
    async def scan_organization(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive data discovery scan"""
        results = {
            'scan_id': self._generate_scan_id(),
            'start_time': time.time(),
            'discoveries': [],
            'statistics': defaultdict(int)
        }
        
        # Run scanners in parallel
        scan_tasks = []
        for scanner_name, scanner in self.scanners.items():
            if scan_config.get(scanner_name, {}).get('enabled', True):
                task = self._run_scanner(scanner, scan_config[scanner_name])
                scan_tasks.append(task)
                
        discoveries = await asyncio.gather(*scan_tasks)
        
        # Classify discovered data
        for discovery_batch in discoveries:
            for discovery in discovery_batch:
                classification = await self.classification_engine.classify(
                    discovery['sample'],
                    discovery['context']
                )
                
                discovery['classification'] = classification
                results['discoveries'].append(discovery)
                results['statistics'][classification['category']] += 1
                
        results['end_time'] = time.time()
        results['total_discovered'] = len(results['discoveries'])
        
        # Generate risk report
        results['risk_report'] = self._generate_risk_report(results)
        
        return results
    
    def _generate_risk_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment from discovery results"""
        report = {
            'high_risk_findings': [],
            'compliance_gaps': [],
            'recommendations': []
        }
        
        # Analyze findings
        for discovery in scan_results['discoveries']:
            if discovery['classification']['category'] in [
                DataCategory.PCI.value, 
                DataCategory.PHI.value
            ]:
                if not discovery.get('encrypted', False):
                    report['high_risk_findings'].append({
                        'location': discovery['location'],
                        'type': discovery['classification']['category'],
                        'risk': 'Unencrypted sensitive data'
                    })
                    
        return report


# Advanced Configuration
class DLPConfiguration:
    """Enhanced configuration management"""
    
    def __init__(self):
        self.config = {}
        self.policy_templates = {}
        self.compliance_mappings = {}
        
    def load_configuration(self, config_path: str):
        """Load configuration with validation"""
        with open(config_path, 'r') as f:
            raw_config = json.load(f)
            
        # Validate configuration
        self._validate_config(raw_config)
        
        # Apply defaults
        self.config = self._apply_defaults(raw_config)
        
        # Load compliance mappings
        self._load_compliance_mappings()
        
    def generate_policy_from_compliance(self, 
                                      compliance_framework: str) -> Dict[str, Any]:
        """Generate DLP policy from compliance requirements"""
        if compliance_framework not in self.compliance_mappings:
            raise ValueError(f"Unknown compliance framework: {compliance_framework}")
            
        mapping = self.compliance_mappings[compliance_framework]
        
        policy = {
            'name': f"{compliance_framework}_auto_generated",
            'description': f"Auto-generated policy for {compliance_framework} compliance",
            'rules': []
        }
        
        # Generate rules based on compliance requirements
        for requirement in mapping['requirements']:
            rule = self._generate_rule_from_requirement(requirement)
            policy['rules'].append(rule)
            
        return policy
    
    def _generate_rule_from_requirement(self, 
                                      requirement: Dict[str, Any]) -> Dict[str, Any]:
        """Convert compliance requirement to DLP rule"""
        rule = {
            'id': requirement['id'],
            'description': requirement['description'],
            'patterns': [],
            'actions': []
        }
        
        # Map data types to patterns
        for data_type in requirement['protected_data_types']:
            if data_type == 'credit_card':
                rule['patterns'].append({
                    'type': 'regex',
                    'pattern': r'\b(?:\d[ -]*?){13,16}\b',
                    'validation': 'luhn'
                })
            elif data_type == 'ssn':
                rule['patterns'].append({
                    'type': 'regex',
                    'pattern': r'\b\d{3}-\d{2}-\d{4}\b'
                })
                
        # Map requirements to actions
        if requirement.get('encryption_required'):
            rule['actions'].append('encrypt')
        if requirement.get('access_logging_required'):
            rule['actions'].append('log')
        if requirement.get('block_unauthorized_transfer'):
            rule['actions'].append('block')
            
        return rule


# Performance Monitoring
class PerformanceMonitor:
    """Monitor DLP system performance"""
    
    def __init__(self):
        self.metrics = defaultdict(list)
        self.thresholds = {
            'latency_ms': 100,
            'cpu_percent': 25,
            'memory_mb': 512,
            'cache_hit_rate': 0.8
        }
        
    async def record_metric(self, metric_name: str, value: float):
        """Record performance metric"""
        timestamp = time.time()
        self.metrics[metric_name].append({
            'timestamp': timestamp,
            'value': value
        })
        
        # Check thresholds
        if metric_name in self.thresholds:
            if value > self.thresholds[metric_name]:
                await self._trigger_performance_alert(metric_name, value)
                
    async def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance report"""
        report = {
            'timestamp': time.time(),
            'metrics': {}
        }
        
        for metric_name, values in self.metrics.items():
            if values:
                recent_values = [v['value'] for v in values[-100:]]
                report['metrics'][metric_name] = {
                    'current': recent_values[-1],
                    'average': np.mean(recent_values),
                    'p95': np.percentile(recent_values, 95),
                    'p99': np.percentile(recent_values, 99),
                    'max': max(recent_values)
                }
                
        return report