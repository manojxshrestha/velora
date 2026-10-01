"""Packaged sources for the local OpenAI-compatible opencode bridge.

``velora.bridge_cli`` seeds these files into a writable runtime directory
(``$VELORA_BRIDGE_HOME`` or ``$XDG_DATA_HOME/velora/bridge``) and runs
``npm install`` there once, so a plain ``pip install velora`` can run
``velora serve-bridge`` without a source checkout.
"""
