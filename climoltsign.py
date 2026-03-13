#!/usr/bin/env python3
"""
MOLTSIGN CLI Tool - Sign and verify MOLTBOOK skills
"""

import os
import sys
import json
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from core.signature import SignatureManager, PermissionLevel, SkillSignature

console = Console()
error_console = Console(stderr=True, style="bold red")

@click.group()
def cli():
    """MOLTBOOK Evolution SSA - Skill Signing Tool"""
    pass


@cli.command()
@click.option('--output-dir', '-o', default='./keys', help='Output directory for keys')
def genkeys(output_dir: str):
    """Generate new Ed25519 keypair for signing skills"""
    
    console