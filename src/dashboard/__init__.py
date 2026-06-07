"""Read-only local web dashboard for Gleipnir IDS."""

from src.dashboard.app import DashboardError, create_app

__all__ = ["DashboardError", "create_app"]
