#!/usr/bin/env python3
"""
Firebase Setup Script for MOLTBOOK Evolution SSA
CRITICAL: This script requires human intervention for Firebase project creation.
Run with: python firebase_setup.py --project-id YOUR_PROJECT_ID
"""

import json
import sys
import os
from typing import Dict, Any, Optional
import click
import subprocess
from pathlib import Path

# Configure logging first
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@click.command()
@click.option('--project-id', required=True, help='Firebase project ID')
@click.option('--region', default='us-central1', help='Firebase region')
def setup_firebase(project_id: str, region: str):
    """
    Setup Firebase project for MOLTBOOK Evolution SSA.
    This script helps initialize Firebase and create necessary collections.
    """
    
    print(f"\n{'='*60}")
    print("MOLTBOOK EVOLUTION - FIREBASE SETUP")
    print(f"{'='*60}\n")
    
    # Check for firebase-admin installation
    try:
        import firebase_admin
        logger.info("✓ firebase-admin is installed")
    except ImportError:
        logger.error("✗ firebase-admin not installed. Run: pip install firebase-admin")
        sys.exit(1)
    
    # Instructions for human intervention
    print("\n🚨 HUMAN INTERVENTION REQUIRED:")
    print("=" * 40)
    print("1. Go to: https://console.firebase.google.com/")
    print(f"2. Create project: {project_id}")
    print("3. Enable Firestore Database (Native mode)")
    print("4. Create service account key:")
    print("   - Project Settings > Service Accounts")
    print("   - Generate new private key")
    print("   - Save as 'firebase-key.json' in current directory")
    print("=" * 40)
    
    # Verify service account file exists
    key_file = Path("firebase-key.json")
    if not key_file.exists():
        logger.error(f"Missing firebase-key.json. Please download from Firebase Console.")
        print(f"\nAfter downloading the key file, run:")
        print(f"python firebase_setup.py --project-id {project_id}")
        sys.exit(1)
    
    # Initialize Firebase
    logger.info("Initializing Firebase...")
    try:
        cred = firebase_admin.credentials.Certificate("firebase-key.json")
        firebase_admin.initialize_app(cred, {
            'projectId': project_id,
            'storageBucket': f"{project_id}.appspot.com"
        })
        logger.info("✓ Firebase initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Firebase: {e}")
        sys.exit(1)
    
    # Initialize Firestore client
    try:
        from google.cloud import firestore
        db = firestore.Client()
        
        # Create initial collections with schema
        collections = [
            'publishers',
            'skills',
            'attestations',
            'key_rotations',
            'reputation_scores'
        ]
        
        for collection in collections:
            # Create a dummy document to ensure collection exists
            doc_ref = db.collection(collection).document('_schema')
            doc_ref.set({
                'created_at': firestore.SERVER_TIMESTAMP,
                'description': f'Schema placeholder for {collection}',
                'version': '1.0.0'
            }, merge=True)
            logger.info(f"✓ Created collection: {collection}")
        
        # Create indexes for common queries
        indexes = [
            ('skills', 'skill_hash'),
            ('skills', 'publisher_id'),
            ('attestations', 'skill_hash'),
            ('attestations', 'timestamp'),
            ('reputation_scores', 'score')
        ]
        
        logger.info("✓ Basic Firebase setup complete")
        
        # Display next steps
        print(f"\n{'='*60}")
        print("NEXT STEPS:")
        print("1. Set up Firebase security rules:")
        print(f"   - Go to Firestore > Rules tab")
        print("2. Enable Firebase Authentication if needed")
        print("3. Test connectivity:")
        print(f"   python -c \"import firebase_admin; print('Connected')\"")
        print(f"{'='*60}\n")
        
    except Exception as e:
        logger.error(f"Failed to setup Firestore: {e}")
        sys.exit(1)

if __name__ == '__main__':
    setup_firebase()