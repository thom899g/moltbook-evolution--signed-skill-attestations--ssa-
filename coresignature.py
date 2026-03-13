"""
Cryptographic signing and verification for MOLTBOOK SSA.
Implements Ed25519 signatures with enhanced metadata.
"""

import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import logging

logger = logging.getLogger(__name__)


class PermissionLevel(Enum):
    """Execution permission levels for skills"""
    READ_ONLY = "read_only"
    NETWORK_LIMITED = "network_limited"
    FULL_ACCESS = "full_access"
    SANDBOXED = "sandboxed"


@dataclass
class SkillSignature:
    """Enhanced skill signature with execution context"""
    skill_hash: str
    publisher_key: str
    required_ee_context: Dict[str, Any]
    reputation_proof: Optional[Dict[str, Any]] = None
    upgrade_chain: Optional[list] = None
    expiration: Optional[str] = None
    revocation_binding: Optional[str] = None
    timestamp: str = None
    version: str = "1.0.0"
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        # Remove None values for cleaner JSON
        return {k: v for k, v in data.items() if v is not None}


class SignatureManager:
    """Manages signing and verification of skills"""
    
    def __init__(self, key_path: Optional[str] = None):
        self.private_key = None
        self.public_key = None
        self.key_path = key_path
        
        if key_path:
            self.load_keypair(key_path)
    
    def generate_keypair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generate new Ed25519 keypair"""
        logger.info("Generating new Ed25519 keypair")
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def save_keypair(self, private_path: str, public_path: str) -> None:
        """Save keypair to files"""
        if not self.private_key or not self.public_key:
            raise ValueError("No keypair generated or loaded")
        
        # Save private key (password protected in production)
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(private_path, 'wb') as f:
            f.write(private_bytes)
        
        # Save public key
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_path, 'wb') as f:
            f.write(public_bytes)
        
        logger.info(f"Keypair saved: {private_path}, {public_path}")
    
    def load_keypair(self, base_path: str) -> None:
        """Load keypair from files"""
        private_path = f"{base_path}.pem"
        public_path = f"{base_path}.pub"
        
        try:
            with open(private_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            
            with open(public_path, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(f.read())
            
            logger.info(f"Keypair loaded from {base_path}")
        except FileNotFoundError as e:
            logger.error(f"Key files not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load keypair: {e}")
            raise
    
    def hash_skill(self, skill_content: str) -> str:
        """Calculate SHA-256 hash of skill content"""
        hash_obj = hashlib.sha256(skill_content.encode('utf-8'))
        return f"sha256:{hash_obj.hexdigest()}"
    
    def create_signature(self, skill_path: str, 
                        ee_context: Dict[str, Any],
                        permissions: PermissionLevel = PermissionLevel.SANDBOXED,
                        expiration_days: int = 365) -> Tuple[str, SkillSignature]:
        """
        Create signed skill with enhanced signature
        
        Args:
            skill_path: Path to skill.md file
            ee_context: Execution environment context requirements
            permissions: Permission level for the skill
            expiration_days: Days until signature expires
            
        Returns:
            Tuple of (signed_skill_content, signature_object)
        """
        
        # Read skill content
        try:
            with open(skill_path, 'r', encoding='utf-8') as f:
                skill_content = f.read()
        except FileNotFoundError:
            logger.error(f"Skill file not found: {skill_path}")
            raise
        
        # Calculate skill hash
        skill_hash = self.hash_skill(skill_content)
        
        # Get public key fingerprint
        if not self.public_key:
            raise ValueError("No public key loaded")
        
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:16]
        
        # Create signature metadata
        expiration = None
        if expiration_days:
            expiration_dt = datetime.now(timezone.utc) + datetime.timedelta(days=expiration_days)
            expiration = expiration_dt.isoformat()
        
        signature = SkillSignature(
            skill_hash=skill_hash,
            publisher_key=f"ed25519:{pub_fingerprint}",
            required_ee_context={
                "attestation_hash": ee_context.get("attestation_hash", ""),
                "min_reputation_score": ee_context.get("min_reputation_score", 0),
                "permission_boundaries": [permissions.value],
                "allowed_envs": ee_context.get("allowed_envs", [])
            },
            expiration=expiration,
            version="1.0.0"
        )
        
        # Create signature over skill hash + metadata
        signature_dict = signature.to_dict()
        signature_json = json.dumps(signature_dict, sort_keys=True)
        message = f"{skill_hash}|{signature_json}".encode('utf-8')
        
        if not self.private_key:
            raise ValueError("No private key loaded for signing")
        
        # Sign the message
        crypto_signature = self.private_key.sign(message)
        b64_signature = base64.b64encode(crypto_signature).decode('utf-8')
        
        # Create signed document
        signed_doc = {
            "skill_content": skill_content,
            "signature_metadata": signature_dict,
            "signature": b64_signature,
            "signature_format": "ed25519_base64"
        }
        
        signed_yaml = yaml.dump(signed_doc, default_flow_style=False)
        
        logger.info(f"Created signature for {skill_path} (hash: {skill_hash[:16]}...)")
        return signed_yaml, signature
    
    def verify_signature(self, signed_content: str) -> Tuple[bool, Optional[SkillSignature]]:
        """
        Verify a signed skill
        
        Args:
            signed_content: YAML content with signature
            
        Returns:
            Tuple of (is_valid, signature_object)
        """
        try:
            # Parse signed document
            doc = yaml.safe_load(signed_content)
            
            if not all(k in doc for k in ['skill_content', 'signature_metadata', 'signature']):
                logger.error("Invalid signed document structure")
                return False, None
            
            # Extract components
            skill_content = doc['skill_content']
            signature_metadata = doc['signature_metadata']
            b64_signature = doc['signature']
            
            # Recalculate skill hash
            skill_hash = self.hash_skill(skill_content)
            
            if skill_hash != signature_metadata.get('skill_hash'):
                logger.error(f"Skill hash mismatch: {skill_hash[:16]}... vs {signature_metadata.get('skill_hash')[:16]}...")
                return False, None
            
            # Check expiration
            expiration = signature_metadata.get('expiration')
            if expiration:
                exp_dt = datetime.fromisoformat(expiration.replace('Z', '+00:00'))
                if datetime.now(timezone.utc) > exp_dt:
                    logger.warning(f"Signature expired on {expiration}")
                    # Still verify signature, but note it's expired
            
            # Recreate message for verification
            signature_json = json.dumps(signature_metadata, sort_keys=True)
            message = f"{skill_hash}|{signature_json}".encode('utf-8')
            
            # Decode signature
            crypto_signature = base64.b64decode(b64_signature)
            
            # Load public key from metadata (in production, would look up from registry)
            # For now, we assume we have the public key loaded
            if not self.public_key:
                logger.error("No public key loaded for verification")
                return False, None
            
            # Verify signature
            try:
                self.public_key.verify(crypto_signature, message)
                logger.info(f"✓ Signature verified for skill: {skill_hash[:16]}...")
                
                # Convert metadata back to SkillSignature object
                signature_obj = SkillSignature(**signature_metadata)
                return True, signature_obj
                
            except InvalidSignature:
                logger.error("✗ Invalid signature")
                return False, None
                
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False, None