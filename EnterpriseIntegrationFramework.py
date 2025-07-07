#!/usr/bin/env python3
"""
DLP v2.0 Enterprise Integration Framework
Comprehensive integration modules for various enterprise systems
"""

import asyncio
import json
import hashlib
import hmac
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
import aiohttp
import jwt
from cryptography.fernet import Fernet
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
import logging

# ============================================
# Core Integration Framework
# ============================================

@dataclass
class IntegrationConfig:
    """Base configuration for all integrations"""
    name: str
    enabled: bool
    api_endpoint: str
    auth_method: str  # oauth2, api_key, saml, certificate
    credentials: Dict[str, str]
    retry_policy: Dict[str, int] = field(default_factory=lambda: {
        'max_retries': 3,
        'backoff_factor': 2,
        'timeout': 30
    })
    rate_limit: Dict[str, int] = field(default_factory=lambda: {
        'calls_per_minute': 60,
        'burst_size': 10
    })

class BaseIntegration(ABC):
    """Base class for all DLP integrations"""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.logger = logging.getLogger(f"dlp.integration.{config.name}")
        self._session: Optional[aiohttp.ClientSession] = None
        self._rate_limiter = RateLimiter(
            calls_per_minute=config.rate_limit['calls_per_minute'],
            burst_size=config.rate_limit['burst_size']
        )
        
    async def __aenter__(self):
        self._session = aiohttp.ClientSession()
        await self.authenticate()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()
            
    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the external system"""
        pass
        
    @abstractmethod
    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Send DLP event to external system"""
        pass
        
    @abstractmethod
    async def query_data(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query data from external system"""
        pass
        
    async def _make_request(self, 
                          method: str, 
                          url: str, 
                          **kwargs) -> aiohttp.ClientResponse:
        """Make HTTP request with retry logic"""
        await self._rate_limiter.acquire()
        
        for attempt in range(self.config.retry_policy['max_retries']):
            try:
                async with self._session.request(
                    method, url, 
                    timeout=aiohttp.ClientTimeout(
                        total=self.config.retry_policy['timeout']
                    ),
                    **kwargs
                ) as response:
                    if response.status < 500:
                        return response
                    
                    # Server error, retry with backoff
                    if attempt < self.config.retry_policy['max_retries'] - 1:
                        wait_time = (
                            self.config.retry_policy['backoff_factor'] ** attempt
                        )
                        await asyncio.sleep(wait_time)
                        
            except aiohttp.ClientError as e:
                self.logger.error(f"Request failed: {e}")
                if attempt == self.config.retry_policy['max_retries'] - 1:
                    raise
                    
        raise Exception("Max retries exceeded")

# ============================================
# SIEM Integrations
# ============================================

class SplunkIntegration(BaseIntegration):
    """Splunk Enterprise/Cloud integration"""
    
    async def authenticate(self) -> bool:
        """Authenticate with Splunk"""
        auth_url = f"{self.config.api_endpoint}/services/auth/login"
        
        async with self._session.post(
            auth_url,
            data={
                'username': self.config.credentials['username'],
                'password': self.config.credentials['password']
            }
        ) as response:
            if response.status == 200:
                data = await response.text()
                # Parse XML response
                root = ET.fromstring(data)
                session_key = root.find('.//sessionKey').text
                self._session.headers.update({
                    'Authorization': f'Splunk {session_key}'
                })
                return True
            return False
            
    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to Splunk HEC"""
        hec_url = f"{self.config.api_endpoint}/services/collector/event"
        
        splunk_event = {
            'time': event.get('timestamp', datetime.utcnow().timestamp()),
            'source': 'dlp_v2',
            'sourcetype': 'dlp:event',
            'event': event
        }
        
        response = await self._make_request(
            'POST',
            hec_url,
            headers={
                'Authorization': f"Splunk {self.config.credentials['hec_token']}"
            },
            json=splunk_event
        )
        
        return response.status == 200
        
    async def query_data(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query Splunk for historical data"""
        search_url = f"{self.config.api_endpoint}/services/search/jobs"
        
        # Create search job
        search_query = self._build_splunk_query(query)
        
        async with self._session.post(
            search_url,
            data={
                'search': search_query,
                'output_mode': 'json',
                'exec_mode': 'oneshot'
            }
        ) as response:
            if response.status == 200:
                data = await response.json()
                return data.get('results', [])
            return []
            
    def _build_splunk_query(self, query: Dict[str, Any]) -> str:
        """Build SPL query from DLP query"""
        base_query = f"search index=dlp sourcetype=dlp:event"
        
        if 'user' in query:
            base_query += f" user={query['user']}"
        if 'time_range' in query:
            base_query += f" earliest={query['time_range']['start']}"
            base_query += f" latest={query['time_range']['end']}"
        if 'risk_score' in query:
            base_query += f" risk_score>={query['risk_score']}"
            
        return base_query

class ElasticsearchIntegration(BaseIntegration):
    """Elasticsearch/ELK Stack integration"""
    
    async def authenticate(self) -> bool:
        """Authenticate with Elasticsearch"""
        if self.config.auth_method == 'api_key':
            self._session.headers.update({
                'Authorization': f"ApiKey {self.config.credentials['api_key']}"
            })
        elif self.config.auth_method == 'basic':
            auth_str = f"{self.config.credentials['username']}:{self.config.credentials['password']}"
            encoded = base64.b64encode(auth_str.encode()).decode()
            self._session.headers.update({
                'Authorization': f"Basic {encoded}"
            })
        return True
        
    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Index event in Elasticsearch"""
        index_name = f"dlp-events-{datetime.utcnow().strftime('%Y.%m.%d')}"
        
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/{index_name}/_doc",
            json=event
        )
        
        return response.status in [200, 201]
        
    async def query_data(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query Elasticsearch"""
        search_body = self._build_es_query(query)
        
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/dlp-events-*/_search",
            json=search_body
        )
        
        if response.status == 200:
            data = await response.json()
            return [hit['_source'] for hit in data['hits']['hits']]
        return []
        
    def _build_es_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Build Elasticsearch query"""
        must_clauses = []
        
        if 'user' in query:
            must_clauses.append({
                'term': {'user.keyword': query['user']}
            })
            
        if 'risk_score' in query:
            must_clauses.append({
                'range': {'risk_score': {'gte': query['risk_score']}}
            })
            
        return {
            'query': {
                'bool': {
                    'must': must_clauses
                }
            },
            'size': query.get('size', 100),
            'sort': [{'timestamp': 'desc'}]
        }

# ============================================
# SOAR/Orchestration Integrations
# ============================================

class PaloAltoCortexIntegration(BaseIntegration):
    """Palo Alto Cortex XSOAR integration"""
    
    async def authenticate(self) -> bool:
        """Authenticate with Cortex XSOAR"""
        self._session.headers.update({
            'x-xdr-auth-id': self.config.credentials['auth_id'],
            'Authorization': self.config.credentials['api_key'],
            'Content-Type': 'application/json'
        })
        return True
        
    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Create incident in Cortex XSOAR"""
        incident = self._convert_to_incident(event)
        
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/incidents",
            json=incident
        )
        
        return response.status == 200
        
    async def trigger_playbook(self, 
                             playbook_id: str, 
                             context: Dict[str, Any]) -> str:
        """Trigger XSOAR playbook"""
        playbook_data = {
            'playbookId': playbook_id,
            'context': context,
            'createInvestigation': True
        }
        
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/playbook/run",
            json=playbook_data
        )
        
        if response.status == 200:
            data = await response.json()
            return data['investigationId']
        return None
        
    def _convert_to_incident(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DLP event to XSOAR incident"""
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        
        return {
            'name': f"DLP Alert: {event.get('policy_name', 'Unknown')}",
            'type': 'DLP Violation',
            'severity': severity_map.get(event.get('severity', 'medium'), 2),
            'occurred': event.get('timestamp'),
            'details': json.dumps(event),
            'labels': [
                {'type': 'DLP', 'value': 'true'},
                {'type': 'RiskScore', 'value': str(event.get('risk_score', 0))},
                {'type': 'DataClassification', 'value': event.get('classification', 'unknown')}
            ],
            'customFields': {
                'dlpuser': event.get('user'),
                'dlppolicyid': event.get('policy_id'),
                'dlpaction': event.get('action')
            }
        }

class ServiceNowIntegration(BaseIntegration):
    """ServiceNow integration for incident management"""
    
    async def authenticate(self) -> bool:
        """OAuth2 authentication with ServiceNow"""
        token_url = f"{self.config.api_endpoint}/oauth_token.do"
        
        async with self._session.post(
            token_url,
            data={
                'grant_type': 'client_credentials',
                'client_id': self.config.credentials['client_id'],
                'client_secret': self.config.credentials['client_secret']
            }
        ) as response:
            if response.status == 200:
                data = await response.json()
                self._session.headers.update({
                    'Authorization': f"Bearer {data['access_token']}"
                })
                return True
        return False
        
    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Create incident in ServiceNow"""
        incident = {
            'short_description': f"DLP Alert: {event.get('description', 'Data Loss Prevention Alert')}",
            'description': self._format_incident_description(event),
            'impact': self._calculate_impact(event),
            'urgency': self._calculate_urgency(event),
            'category': 'Security',
            'subcategory': 'Data Loss Prevention',
            'assignment_group': 'Security Operations',
            'caller_id': event.get('user', 'DLP System'),
            'u_risk_score': event.get('risk_score', 0),
            'u_data_classification': event.get('classification', 'Unknown')
        }
        
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/api/now/table/incident",
            json=incident
        )
        
        return response.status == 201
        
    def _calculate_impact(self, event: Dict[str, Any]) -> int:
        """Calculate ServiceNow impact based on DLP event"""
        risk_score = event.get('risk_score', 0)
        if risk_score >= 80:
            return 1  # High
        elif risk_score >= 50:
            return 2  # Medium
        return 3  # Low
        
    def _calculate_urgency(self, event: Dict[str, Any]) -> int:
        """Calculate ServiceNow urgency"""
        if event.get('action') == 'block':
            return 1  # High
        elif event.get('real_time', False):
            return 2  # Medium
        return 3  # Low

# ============================================
# Identity & Access Management Integrations
# ============================================

class OktaIntegration(BaseIntegration):
    """Okta integration for identity context and adaptive auth"""
    
    async def authenticate(self) -> bool:
        """Authenticate with Okta API"""
        self._session.headers.update({
            'Authorization': f"SSWS {self.config.credentials['api_token']}",
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        return True
        
    async def get_user_context(self, user_id: str) -> Dict[str, Any]:
        """Get user context from Okta"""
        response = await self._make_request(
            'GET',
            f"{self.config.api_endpoint}/api/v1/users/{user_id}"
        )
        
        if response.status == 200:
            user_data = await response.json()
            
            # Get user groups
            groups_response = await self._make_request(
                'GET',
                f"{self.config.api_endpoint}/api/v1/users/{user_id}/groups"
            )
            groups = await groups_response.json() if groups_response.status == 200 else []
            
            # Get user's recent auth events
            auth_events = await self._get_auth_events(user_id)
            
            return {
                'profile': user_data['profile'],
                'status': user_data['status'],
                'groups': [g['profile']['name'] for g in groups],
                'risk_factors': self._analyze_risk_factors(user_data, auth_events),
                'last_login': user_data.get('lastLogin'),
                'mfa_enrolled': len(user_data.get('credentials', {}).get('provider', [])) > 1
            }
        return {}
        
    async def trigger_step_up_auth(self, 
                                 user_id: str, 
                                 session_id: str,
                                 factor_type: str = 'push') -> bool:
        """Trigger step-up authentication"""
        # Create authentication transaction
        transaction_data = {
            'username': user_id,
            'factor': factor_type,
            'sessionToken': session_id
        }
        
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/api/v1/authn",
            json=transaction_data
        )
        
        if response.status == 200:
            data = await response.json()
            # Trigger MFA challenge
            if data['status'] == 'MFA_REQUIRED':
                factor_id = data['_embedded']['factors'][0]['id']
                challenge_response = await self._make_request(
                    'POST',
                    f"{self.config.api_endpoint}/api/v1/authn/factors/{factor_id}/verify",
                    json={'stateToken': data['stateToken']}
                )
                return challenge_response.status == 200
        return False
        
    async def suspend_user(self, user_id: str, reason: str) -> bool:
        """Suspend user account due to DLP violation"""
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/api/v1/users/{user_id}/lifecycle/suspend",
            json={'reason': reason}
        )
        return response.status == 200
        
    def _analyze_risk_factors(self, 
                            user_data: Dict[str, Any], 
                            auth_events: List[Dict[str, Any]]) -> List[str]:
        """Analyze user risk factors"""
        risk_factors = []
        
        # Check for suspicious auth patterns
        failed_logins = sum(1 for e in auth_events if e.get('outcome', {}).get('result') == 'FAILURE')
        if failed_logins > 5:
            risk_factors.append('multiple_failed_logins')
            
        # Check for location anomalies
        locations = [e.get('client', {}).get('geographicalContext', {}).get('country') 
                    for e in auth_events]
        if len(set(locations)) > 3:
            risk_factors.append('multiple_geo_locations')
            
        # Check account age
        created_date = datetime.fromisoformat(user_data.get('created', '').replace('Z', '+00:00'))
        if (datetime.utcnow() - created_date.replace(tzinfo=None)).days < 30:
            risk_factors.append('new_account')
            
        return risk_factors

class ActiveDirectoryIntegration(BaseIntegration):
    """Active Directory/LDAP integration"""
    
    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self._ldap_conn = None
        
    async def authenticate(self) -> bool:
        """Authenticate with AD/LDAP"""
        import ldap3
        
        server = ldap3.Server(
            self.config.api_endpoint,
            use_ssl=True,
            get_info=ldap3.ALL
        )
        
        self._ldap_conn = ldap3.Connection(
            server,
            user=self.config.credentials['bind_dn'],
            password=self.config.credentials['bind_password'],
            auto_bind=True
        )
        
        return self._ldap_conn.bound
        
    async def get_user_attributes(self, username: str) -> Dict[str, Any]:
        """Get user attributes from AD"""
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        
        self._ldap_conn.search(
            search_base=self.config.credentials['search_base'],
            search_filter=search_filter,
            attributes=['*']
        )
        
        if self._ldap_conn.entries:
            entry = self._ldap_conn.entries[0]
            return {
                'dn': entry.entry_dn,
                'groups': self._get_user_groups(entry),
                'department': str(entry.department) if hasattr(entry, 'department') else None,
                'manager': str(entry.manager) if hasattr(entry, 'manager') else None,
                'title': str(entry.title) if hasattr(entry, 'title') else None,
                'accountStatus': 'active' if not entry.userAccountControl.value & 2 else 'disabled',
                'lastLogon': entry.lastLogon.value if hasattr(entry, 'lastLogon') else None
            }
        return {}
        
    async def disable_account(self, username: str) -> bool:
        """Disable AD account"""
        user_dn = await self._get_user_dn(username)
        if user_dn:
            # Set userAccountControl flag to disable account
            return self._ldap_conn.modify(
                user_dn,
                {'userAccountControl': [(ldap3.MODIFY_REPLACE, [514])]}
            )
        return False
        
    def _get_user_groups(self, user_entry) -> List[str]:
        """Extract user group memberships"""
        groups = []
        if hasattr(user_entry, 'memberOf'):
            for group_dn in user_entry.memberOf:
                # Extract CN from DN
                cn_match = re.match(r'CN=([^,]+)', str(group_dn))
                if cn_match:
                    groups.append(cn_match.group(1))
        return groups

# ============================================
# Cloud Platform Integrations
# ============================================

class AWSIntegration(BaseIntegration):
    """AWS integration for cloud workload protection"""
    
    async def authenticate(self) -> bool:
        """Authenticate with AWS"""
        import boto3
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        
        self._session_credentials = boto3.Session(
            aws_access_key_id=self.config.credentials['access_key_id'],
            aws_secret_access_key=self.config.credentials['secret_access_key'],
            region_name=self.config.credentials.get('region', 'us-east-1')
        ).get_credentials()
        
        return True
        
    async def send_to_cloudwatch(self, event: Dict[str, Any]) -> bool:
        """Send event to CloudWatch Logs"""
        import boto3
        
        logs_client = boto3.client(
            'logs',
            aws_access_key_id=self.config.credentials['access_key_id'],
            aws_secret_access_key=self.config.credentials['secret_access_key'],
            region_name=self.config.credentials.get('region', 'us-east-1')
        )
        
        log_event = {
            'timestamp': int(event.get('timestamp', datetime.utcnow().timestamp()) * 1000),
            'message': json.dumps(event)
        }
        
        try:
            logs_client.put_log_events(
                logGroupName='/aws/dlp/events',
                logStreamName=datetime.utcnow().strftime('%Y/%m/%d'),
                logEvents=[log_event]
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to send to CloudWatch: {e}")
            return False
            
    async def quarantine_s3_object(self, 
                                 bucket: str, 
                                 key: str,
                                 reason: str) -> bool:
        """Quarantine S3 object by moving and restricting access"""
        import boto3
        
        s3_client = boto3.client(
            's3',
            aws_access_key_id=self.config.credentials['access_key_id'],
            aws_secret_access_key=self.config.credentials['secret_access_key']
        )
        
        quarantine_bucket = f"{bucket}-dlp-quarantine"
        quarantine_key = f"quarantine/{datetime.utcnow().isoformat()}/{key}"
        
        try:
            # Copy object to quarantine
            s3_client.copy_object(
                CopySource={'Bucket': bucket, 'Key': key},
                Bucket=quarantine_bucket,
                Key=quarantine_key,
                TagSet=f"dlp-quarantine-reason={reason}"
            )
            
            # Delete original
            s3_client.delete_object(Bucket=bucket, Key=key)
            
            # Apply restrictive bucket policy
            await self._apply_quarantine_policy(quarantine_bucket)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to quarantine S3 object: {e}")
            return False
            
    async def enable_guardduty_protection(self, resource_arn: str) -> bool:
        """Enable GuardDuty threat detection for resource"""
        import boto3
        
        guardduty = boto3.client(
            'guardduty',
            aws_access_key_id=self.config.credentials['access_key_id'],
            aws_secret_access_key=self.config.credentials['secret_access_key']
        )
        
        # Implementation for GuardDuty integration
        return True

class AzureIntegration(BaseIntegration):
    """Microsoft Azure integration"""
    
    async def authenticate(self) -> bool:
        """Authenticate with Azure AD"""
        from azure.identity.aio import ClientSecretCredential
        
        self._credential = ClientSecretCredential(
            tenant_id=self.config.credentials['tenant_id'],
            client_id=self.config.credentials['client_id'],
            client_secret=self.config.credentials['client_secret']
        )
        
        token = await self._credential.get_token("https://management.azure.com/.default")
        self._session.headers.update({
            'Authorization': f'Bearer {token.token}'
        })
        
        return True
        
    async def send_to_sentinel(self, event: Dict[str, Any]) -> bool:
        """Send event to Azure Sentinel"""
        workspace_id = self.config.credentials['workspace_id']
        
        # Format for Azure Sentinel
        sentinel_event = {
            'TimeGenerated': datetime.utcnow().isoformat(),
            'SourceSystem': 'DLP_v2',
            'EventType': 'DLPViolation',
            'EventData': json.dumps(event)
        }
        
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/workspaces/{workspace_id}/api/logs",
            json=[sentinel_event]
        )
        
        return response.status == 200
        
    async def apply_information_protection(self, 
                                         file_path: str,
                                         classification: str) -> bool:
        """Apply Microsoft Information Protection labels"""
        # Implementation for MIP SDK
        return True

# ============================================
# Collaboration Platform Integrations
# ============================================

class SlackIntegration(BaseIntegration):
    """Slack integration for notifications and alerts"""
    
    async def authenticate(self) -> bool:
        """OAuth2 authentication with Slack"""
        self._session.headers.update({
            'Authorization': f"Bearer {self.config.credentials['bot_token']}"
        })
        return True
        
    async def send_alert(self, 
                       channel: str, 
                       event: Dict[str, Any],
                       interactive: bool = True) -> bool:
        """Send formatted alert to Slack channel"""
        blocks = self._format_alert_blocks(event, interactive)
        
        response = await self._make_request(
            'POST',
            'https://slack.com/api/chat.postMessage',
            json={
                'channel': channel,
                'blocks': blocks,
                'text': f"DLP Alert: {event.get('description', 'Security Alert')}"
            }
        )
        
        return response.status == 200
        
    def _format_alert_blocks(self, 
                           event: Dict[str, Any], 
                           interactive: bool) -> List[Dict[str, Any]]:
        """Format event as Slack blocks"""
        severity_emoji = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '📋',
            'low': 'ℹ️'
        }
        
        blocks = [
            {
                'type': 'header',
                'text': {
                    'type': 'plain_text',
                    'text': f"{severity_emoji.get(event.get('severity', 'medium'), '📋')} DLP Alert"
                }
            },
            {
                'type': 'section',
                'fields': [
                    {
                        'type': 'mrkdwn',
                        'text': f"*Policy:*\n{event.get('policy_name', 'Unknown')}"
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f"*User:*\n{event.get('user', 'Unknown')}"
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f"*Risk Score:*\n{event.get('risk_score', 0)}/100"
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f"*Classification:*\n{event.get('classification', 'Unknown')}"
                    }
                ]
            },
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f"*Description:*\n{event.get('description', 'No description available')}"
                }
            }
        ]
        
        if interactive:
            blocks.append({
                'type': 'actions',
                'elements': [
                    {
                        'type': 'button',
                        'text': {
                            'type': 'plain_text',
                            'text': 'View Details'
                        },
                        'value': event.get('event_id', ''),
                        'action_id': 'view_details'
                    },
                    {
                        'type': 'button',
                        'text': {
                            'type': 'plain_text',
                            'text': 'Acknowledge'
                        },
                        'style': 'primary',
                        'value': event.get('event_id', ''),
                        'action_id': 'acknowledge'
                    },
                    {
                        'type': 'button',
                        'text': {
                            'type': 'plain_text',
                            'text': 'Escalate'
                        },
                        'style': 'danger',
                        'value': event.get('event_id', ''),
                        'action_id': 'escalate'
                    }
                ]
            })
            
        return blocks

class MicrosoftTeamsIntegration(BaseIntegration):
    """Microsoft Teams integration"""
    
    async def authenticate(self) -> bool:
        """Authenticate with Teams webhook or Graph API"""
        if 'webhook_url' in self.config.credentials:
            # Webhook authentication (no auth needed)
            return True
        else:
            # Graph API authentication
            token_url = f"https://login.microsoftonline.com/{self.config.credentials['tenant_id']}/oauth2/v2.0/token"
            
            async with self._session.post(
                token_url,
                data={
                    'client_id': self.config.credentials['client_id'],
                    'client_secret': self.config.credentials['client_secret'],
                    'scope': 'https://graph.microsoft.com/.default',
                    'grant_type': 'client_credentials'
                }
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self._session.headers.update({
                        'Authorization': f"Bearer {data['access_token']}"
                    })
                    return True
        return False
        
    async def send_adaptive_card(self, 
                               channel_id: str,
                               event: Dict[str, Any]) -> bool:
        """Send adaptive card to Teams channel"""
        card = self._create_adaptive_card(event)
        
        if 'webhook_url' in self.config.credentials:
            # Send via webhook
            response = await self._make_request(
                'POST',
                self.config.credentials['webhook_url'],
                json=card
            )
        else:
            # Send via Graph API
            response = await self._make_request(
                'POST',
                f"https://graph.microsoft.com/v1.0/teams/{channel_id}/channels/messages",
                json={
                    'body': {
                        'contentType': 'html',
                        'content': json.dumps(card)
                    }
                }
            )
            
        return response.status in [200, 201, 202]

# ============================================
# Email Security Gateway Integrations
# ============================================

class ProofpointIntegration(BaseIntegration):
    """Proofpoint Email Security integration"""
    
    async def authenticate(self) -> bool:
        """Authenticate with Proofpoint API"""
        auth_header = base64.b64encode(
            f"{self.config.credentials['service_principal']}:{self.config.credentials['secret']}".encode()
        ).decode()
        
        self._session.headers.update({
            'Authorization': f'Basic {auth_header}'
        })
        return True
        
    async def quarantine_email(self, 
                             message_id: str,
                             reason: str) -> bool:
        """Quarantine email in Proofpoint"""
        quarantine_data = {
            'guid': message_id,
            'folder': 'DLP_Quarantine',
            'reason': reason
        }
        
        response = await self._make_request(
            'POST',
            f"{self.config.api_endpoint}/api/v2/quarantine/messages",
            json=quarantine_data
        )
        
        return response.status == 200
        
    async def update_email_policy(self, 
                                policy_update: Dict[str, Any]) -> bool:
        """Update Proofpoint email DLP policy"""
        response = await self._make_request(
            'PUT',
            f"{self.config.api_endpoint}/api/v2/dlp/policies/{policy_update['policy_id']}",
            json=policy_update
        )
        
        return response.status == 200

# ============================================
# Integration Manager
# ============================================

class IntegrationManager:
    """Manages all DLP integrations"""
    
    def __init__(self):
        self.integrations: Dict[str, BaseIntegration] = {}
        self.logger = logging.getLogger("dlp.integration.manager")
        
    async def initialize(self, config_path: str):
        """Initialize all configured integrations"""
        with open(config_path, 'r') as f:
            configs = json.load(f)
            
        for integration_config in configs['integrations']:
            if integration_config['enabled']:
                await self._load_integration(integration_config)
                
    async def _load_integration(self, config: Dict[str, Any]):
        """Load and initialize a single integration"""
        integration_class = {
            'splunk': SplunkIntegration,
            'elasticsearch': ElasticsearchIntegration,
            'cortex_xsoar': PaloAltoCortexIntegration,
            'servicenow': ServiceNowIntegration,
            'okta': OktaIntegration,
            'active_directory': ActiveDirectoryIntegration,
            'aws': AWSIntegration,
            'azure': AzureIntegration,
            'slack': SlackIntegration,
            'teams': MicrosoftTeamsIntegration,
            'proofpoint': ProofpointIntegration
        }.get(config['type'])
        
        if integration_class:
            try:
                integration_config = IntegrationConfig(**config)
                integration = integration_class(integration_config)
                
                async with integration:
                    self.integrations[config['name']] = integration
                    self.logger.info(f"Initialized {config['name']} integration")
                    
            except Exception as e:
                self.logger.error(f"Failed to initialize {config['name']}: {e}")
                
    async def send_event(self, event: Dict[str, Any], targets: List[str] = None):
        """Send event to specified integrations or all if none specified"""
        if targets is None:
            targets = list(self.integrations.keys())
            
        results = {}
        for target in targets:
            if target in self.integrations:
                try:
                    success = await self.integrations[target].send_event(event)
                    results[target] = success
                except Exception as e:
                    self.logger.error(f"Failed to send event to {target}: {e}")
                    results[target] = False
                    
        return results
        
    async def enrich_context(self, 
                           user_id: str,
                           enrichment_sources: List[str] = None) -> Dict[str, Any]:
        """Enrich user context from multiple sources"""
        context = {}
        
        sources = enrichment_sources or ['okta', 'active_directory']
        
        for source in sources:
            if source in self.integrations:
                try:
                    if hasattr(self.integrations[source], 'get_user_context'):
                        source_context = await self.integrations[source].get_user_context(user_id)
                        context[source] = source_context
                except Exception as e:
                    self.logger.error(f"Failed to get context from {source}: {e}")
                    
        return context
        
    async def orchestrate_response(self, 
                                 event: Dict[str, Any],
                                 playbook: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate automated response across integrations"""
        results = {
            'executed_actions': [],
            'failed_actions': [],
            'status': 'completed'
        }
        
        for action in playbook['actions']:
            integration_name = action['integration']
            action_type = action['action']
            
            if integration_name in self.integrations:
                integration = self.integrations[integration_name]
                
                try:
                    if action_type == 'disable_user' and hasattr(integration, 'disable_account'):
                        success = await integration.disable_account(
                            action['parameters']['user_id']
                        )
                    elif action_type == 'quarantine_file' and hasattr(integration, 'quarantine_s3_object'):
                        success = await integration.quarantine_s3_object(
                            action['parameters']['bucket'],
                            action['parameters']['key'],
                            action['parameters']['reason']
                        )
                    elif action_type == 'send_alert' and hasattr(integration, 'send_alert'):
                        success = await integration.send_alert(
                            action['parameters']['channel'],
                            event
                        )
                    else:
                        success = False
                        
                    if success:
                        results['executed_actions'].append(action)
                    else:
                        results['failed_actions'].append(action)
                        
                except Exception as e:
                    self.logger.error(f"Failed to execute action {action_type}: {e}")
                    results['failed_actions'].append(action)
                    
        if results['failed_actions']:
            results['status'] = 'partial_failure'
            
        return results

# ============================================
# Utility Classes
# ============================================

class RateLimiter:
    """Rate limiter for API calls"""
    
    def __init__(self, calls_per_minute: int, burst_size: int):
        self.calls_per_minute = calls_per_minute
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self._lock = asyncio.Lock()
        
    async def acquire(self):
        """Acquire a token to make an API call"""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Refill tokens based on time elapsed
            tokens_to_add = elapsed * (self.calls_per_minute / 60)
            self.tokens = min(self.burst_size, self.tokens + tokens_to_add)
            self.last_update = now
            
            if self.tokens < 1:
                # Wait until we have a token
                wait_time = (1 - self.tokens) / (self.calls_per_minute / 60)
                await asyncio.sleep(wait_time)
                self.tokens = 1
                
            self.tokens -= 1

# ============================================
# Example Usage
# ============================================

async def main():
    """Example integration usage"""
    
    # Initialize integration manager
    manager = IntegrationManager()
    await manager.initialize('integrations_config.json')
    
    # Example DLP event
    dlp_event = {
        'event_id': 'evt_123456',
        'timestamp': datetime.utcnow().isoformat(),
        'user': 'john.doe@company.com',
        'policy_name': 'Credit Card Protection',
        'policy_id': 'pol_cc_001',
        'action': 'block',
        'severity': 'high',
        'risk_score': 85,
        'classification': 'PCI',
        'description': 'Attempted to email credit card data to external recipient',
        'metadata': {
            'source_ip': '192.168.1.100',
            'destination': 'external@gmail.com',
            'file_name': 'customer_data.xlsx',
            'data_volume': '2.3MB'
        }
    }
    
    # Send event to all integrations
    results = await manager.send_event(dlp_event)
    print(f"Event sent to integrations: {results}")
    
    # Enrich user context
    user_context = await manager.enrich_context('john.doe@company.com')
    print(f"User context: {user_context}")
    
    # Orchestrate response
    response_playbook = {
        'name': 'High Risk Response',
        'actions': [
            {
                'integration': 'okta',
                'action': 'trigger_step_up_auth',
                'parameters': {
                    'user_id': 'john.doe@company.com',
                    'factor_type': 'push'
                }
            },
            {
                'integration': 'slack',
                'action': 'send_alert',
                'parameters': {
                    'channel': '#security-alerts'
                }
            },
            {
                'integration': 'servicenow',
                'action': 'create_incident',
                'parameters': {
                    'priority': 'high'
                }
            }
        ]
    }
    
    response_results = await manager.orchestrate_response(dlp_event, response_playbook)
    print(f"Response orchestration results: {response_results}")

if __name__ == "__main__":
    asyncio.run(main())