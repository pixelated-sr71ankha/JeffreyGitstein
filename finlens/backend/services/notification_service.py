"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Notification Service
═══════════════════════════════════════════════════════════════════════════════

Handles all notification operations:
- In-app alert creation and delivery
- Budget limit alerts (triggered when spending approaches/exceeds limits)
- Scam warning alerts (triggered by high-risk detections)
- Portfolio change alerts
- Learning reminders and streak maintenance
- Weekly financial health digest
- Push notification preparation (for mobile integration)
- Email notification templates
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy import select, func, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database import Alert, User, ScanHistory, Expense, db_manager

logger = logging.getLogger("finlens.notifications")


# ═══════════════════════════════════════════════════════════════════════════════
# Alert Templates
# ═══════════════════════════════════════════════════════════════════════════════

ALERT_TEMPLATES = {
    "scam_detected": {
        "alert_type": "scam_warning",
        "title": "🚨 Scam Detected!",
        "message": "A suspicious message was detected with a risk score of {risk_score}/100. It appears to be a {scam_type} scam. Take action immediately.",
        "severity": "critical",
    },
    "scam_warning": {
        "alert_type": "scam_warning",
        "title": "⚠️ Suspicious Message",
        "message": "A message you analyzed has been flagged as suspicious (score: {risk_score}/100). Review the analysis for details.",
        "severity": "warning",
    },
    "budget_80": {
        "alert_type": "budget_limit",
        "title": "💸 Budget Alert: 80% Used",
        "message": "You've spent {spent_pct:.0f}% of your {category} budget this month (₹{spent:,.0f} of ₹{budget:,.0f}). Consider slowing down.",
        "severity": "warning",
    },
    "budget_100": {
        "alert_type": "budget_limit",
        "title": "🚨 Budget Exceeded!",
        "message": "You've exceeded your {category} budget by ₹{overshoot:,.0f}! Current spend: ₹{spent:,.0f} vs budget: ₹{budget:,.0f}.",
        "severity": "critical",
    },
    "streak_warning": {
        "alert_type": "learning_reminder",
        "title": "🔥 Streak at Risk!",
        "message": "Your {streak}-day streak is about to break! Complete a scan today to keep it going.",
        "severity": "info",
    },
    "weekly_digest": {
        "alert_type": "system",
        "title": "📊 Weekly Financial Digest",
        "message": "Here's your weekly summary: {summary}",
        "severity": "info",
    },
    "scam_intelligence": {
        "alert_type": "scam_warning",
        "title": "📢 New Scam Alert",
        "message": "{title}. Stay vigilant and report any similar encounters.",
        "severity": "warning",
    },
    "new_badge": {
        "alert_type": "system",
        "title": "🏆 Badge Earned!",
        "message": "Congratulations! You've earned the '{badge_name}' badge. Keep up the great work!",
        "severity": "info",
    },
    "portfolio_change": {
        "alert_type": "portfolio_change",
        "title": "📈 Portfolio Alert",
        "message": "{message}",
        "severity": "info",
    },
    "market_event": {
        "alert_type": "portfolio_change",
        "title": "🔔 Market Update",
        "message": "{message}",
        "severity": "info",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Notification Service
# ═══════════════════════════════════════════════════════════════════════════════

class NotificationService:
    """
    Manages creation, delivery, and management of user notifications.
    """

    async def create_alert(
        self,
        session: AsyncSession,
        user_id: str,
        alert_type: str,
        title: str,
        message: str,
        severity: str = "info",
        data: Dict[str, Any] = None,
        action_url: str = None,
        related_id: str = None,
    ) -> Dict[str, Any]:
        """
        Create a new alert for a user.

        Returns:
            Created alert data.
        """
        alert = Alert(
            user_id=user_id,
            alert_type=alert_type,
            title=title,
            message=message,
            severity=severity,
            data=data,
            action_url=action_url,
            related_id=related_id,
        )
        session.add(alert)
        await session.flush()

        logger.info(f"Alert created for user {user_id}: {title}")

        return {
            "id": alert.id,
            "alert_type": alert.alert_type,
            "title": alert.title,
            "message": alert.message,
            "severity": alert.severity,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        }

    async def create_from_template(
        self,
        session: AsyncSession,
        user_id: str,
        template_key: str,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Create an alert from a predefined template."""
        template = ALERT_TEMPLATES.get(template_key)
        if not template:
            logger.warning(f"Unknown alert template: {template_key}")
            return None

        try:
            message = template["message"].format(**kwargs)
        except KeyError as e:
            logger.error(f"Missing template variable {e} for template {template_key}")
            return None

        return await self.create_alert(
            session=session,
            user_id=user_id,
            alert_type=template["alert_type"],
            title=template["title"],
            message=message,
            severity=template["severity"],
            data=kwargs,
        )

    async def get_user_alerts(
        self,
        session: AsyncSession,
        user_id: str,
        alert_type: str = None,
        unread_only: bool = False,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get alerts for a user with optional filtering."""
        query = select(Alert).where(Alert.user_id == user_id)

        if alert_type:
            query = query.where(Alert.alert_type == alert_type)

        if unread_only:
            query = query.where(Alert.is_read == False)

        # Get total count
        count_result = await session.execute(
            select(func.count(Alert.id)).where(Alert.user_id == user_id)
        )
        total = count_result.scalar() or 0

        # Get unread count
        unread_result = await session.execute(
            select(func.count(Alert.id)).where(
                Alert.user_id == user_id,
                Alert.is_read == False,
            )
        )
        unread_count = unread_result.scalar() or 0

        # Fetch alerts
        query = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
        result = await session.execute(query)
        alerts = result.scalars().all()

        return {
            "alerts": [
                {
                    "id": a.id,
                    "alert_type": a.alert_type,
                    "title": a.title,
                    "message": a.message,
                    "severity": a.severity,
                    "is_read": a.is_read,
                    "action_url": a.action_url,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in alerts
            ],
            "total": total,
            "unread_count": unread_count,
        }

    async def mark_read(
        self,
        session: AsyncSession,
        user_id: str,
        alert_ids: List[str] = None,
        mark_all: bool = False,
    ) -> int:
        """Mark alerts as read. Returns count of updated alerts."""
        if mark_all:
            result = await session.execute(
                update(Alert)
                .where(Alert.user_id == user_id, Alert.is_read == False)
                .values(is_read=True, read_at=datetime.utcnow())
            )
            return result.rowcount
        elif alert_ids:
            result = await session.execute(
                update(Alert)
                .where(
                    Alert.id.in_(alert_ids),
                    Alert.user_id == user_id,
                )
                .values(is_read=True, read_at=datetime.utcnow())
            )
            return result.rowcount
        return 0

    async def dismiss_alert(
        self,
        session: AsyncSession,
        user_id: str,
        alert_id: str,
    ) -> bool:
        """Dismiss an alert."""
        result = await session.execute(
            update(Alert)
            .where(Alert.id == alert_id, Alert.user_id == user_id)
            .values(is_dismissed=True, is_read=True)
        )
        return result.rowcount > 0

    async def get_alert_summary(
        self,
        session: AsyncSession,
        user_id: str,
    ) -> Dict[str, int]:
        """Get alert count summary by severity."""
        result = await session.execute(
            select(
                Alert.severity,
                func.count(Alert.id)
            )
            .where(Alert.user_id == user_id, Alert.is_dismissed == False)
            .group_by(Alert.severity)
        )
        severity_counts = {row[0]: row[1] for row in result.all()}

        unread_result = await session.execute(
            select(func.count(Alert.id)).where(
                Alert.user_id == user_id,
                Alert.is_read == False,
            )
        )
        unread = unread_result.scalar() or 0

        total_result = await session.execute(
            select(func.count(Alert.id)).where(Alert.user_id == user_id)
        )
        total = total_result.scalar() or 0

        return {
            "total": total,
            "unread": unread,
            "critical": severity_counts.get("critical", 0),
            "warning": severity_counts.get("warning", 0),
            "info": severity_counts.get("info", 0),
        }

    # ─── Automatic Alert Generators ───────────────────────────────

    async def check_budget_alerts(
        self,
        session: AsyncSession,
        user_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Check if any budget alerts need to be triggered.
        Called after expense recording.
        """
        alerts_created = []

        # Get user's expenses this month
        now = datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        expenses = await session.execute(
            select(Expense).where(
                Expense.user_id == user_id,
                Expense.date >= month_start,
                Expense.is_income == False,
            )
        )
        monthly_expenses = expenses.scalars().all()

        # Group by category
        from collections import defaultdict
        category_totals = defaultdict(float)
        for exp in monthly_expenses:
            category_totals[exp.category] += exp.amount

        total_spent = sum(category_totals.values())

        # Check if total spending exceeds 80% of estimated budget
        # (would need user's income data for precise check)
        user_result = await session.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()

        if user and user.annual_income:
            monthly_income = user.annual_income / 12
            spent_pct = (total_spent / monthly_income * 100) if monthly_income > 0 else 0

            if spent_pct >= 100:
                alert = await self.create_from_template(
                    session, user_id, "budget_100",
                    category="overall",
                    spent=total_spent,
                    budget=monthly_income,
                    overshoot=total_spent - monthly_income,
                )
                if alert:
                    alerts_created.append(alert)

            elif spent_pct >= 80:
                alert = await self.create_from_template(
                    session, user_id, "budget_80",
                    category="overall",
                    spent_pct=spent_pct,
                    spent=total_spent,
                    budget=monthly_income,
                )
                if alert:
                    alerts_created.append(alert)

        return alerts_created

    async def check_streak_alerts(
        self,
        session: AsyncSession,
        user_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Check if user's learning streak is at risk."""
        user_result = await session.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()

        if not user or not user.last_active:
            return None

        # Check if last activity was yesterday (streak about to break)
        days_inactive = (datetime.utcnow() - user.last_active).days

        if days_inactive >= 1 and user.streak_days >= 3:
            return await self.create_from_template(
                session, user_id, "streak_warning",
                streak=user.streak_days,
            )

        return None

    async def generate_weekly_digest(
        self,
        session: AsyncSession,
        user_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Generate a weekly financial digest for the user."""
        one_week_ago = datetime.utcnow() - timedelta(days=7)

        # Get scan stats
        scans = await session.execute(
            select(func.count(ScanHistory.id)).where(
                ScanHistory.user_id == user_id,
                ScanHistory.created_at >= one_week_ago,
            )
        )
        scan_count = scans.scalar() or 0

        # Get scam detections
        scams = await session.execute(
            select(func.count(ScanHistory.id)).where(
                ScanHistory.user_id == user_id,
                ScanHistory.created_at >= one_week_ago,
                ScanHistory.risk_score >= 50,
            )
        )
        scam_count = scams.scalar() or 0

        # Get expenses
        expenses = await session.execute(
            select(func.sum(Expense.amount)).where(
                Expense.user_id == user_id,
                Expense.date >= one_week_ago,
                Expense.is_income == False,
            )
        )
        total_spent = expenses.scalar() or 0

        summary = (
            f"You made {scan_count} scans this week, "
            f"detected {scam_count} potential scams, "
            f"and spent ₹{total_spent:,.0f}. "
        )

        if scam_count > 0:
            summary += f"FinLens protected you from {scam_count} suspicious messages! 🛡️"

        return await self.create_from_template(
            session, user_id, "weekly_digest",
            summary=summary,
        )


# Singleton
notification_service = NotificationService()
