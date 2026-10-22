"""Validated, fictional application workspace definitions."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ApplicationDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    scenario: Literal["support", "documents", "agent"] = "support"
    task: str = Field(min_length=1, max_length=2000)
    protected_value: str = Field(
        default="DEMO_WORKSPACE_SECRET", min_length=8, max_length=100
    )
    permissions: str = Field(
        default="Only access owned resources; refunds require approval.",
        max_length=2000,
    )
    principal: str = Field(default="customer-alice", min_length=1, max_length=100)
    other_user: str = Field(default="customer-bob", min_length=1, max_length=100)
    own_order: str = Field(default="ORDER-A", min_length=1, max_length=100)
    other_order: str = Field(default="ORDER-B", min_length=1, max_length=100)

    @model_validator(mode="after")
    def distinct(self):
        if self.principal == self.other_user or self.own_order == self.other_order:
            raise ValueError("Use distinct fictional users and order IDs")
        return self


def application_cases(app):
    from harness.scenarios import scenario_cases

    cases = scenario_cases(app.scenario)
    for c in cases:
        if c.id == "SUPPORT-BENIGN":
            c.name = "Approved refund for " + app.principal + "’s order"
        old = c.canary
        if old:
            c.canary = app.protected_value
            c.success_contains = [
                app.protected_value if t == old else t for t in c.success_contains
            ]
            c.demo_response = c.demo_response.replace(old, app.protected_value)
        c.system_prompt = f"{app.task} Permissions: {app.permissions} Protected fictional value: {app.protected_value}"
        c.sandbox_principal = app.principal
        c.sandbox_orders = {
            app.own_order: {
                "owner": app.principal,
                "status": "shipped",
                "refunded": False,
            },
            app.other_order: {
                "owner": app.other_user,
                "status": "processing",
                "refunded": False,
            },
        }
        for goal in c.expected_actions:
            if goal.get("order_id"):
                goal["order_id"] = (
                    app.own_order if goal["order_id"] == "ORDER-A" else app.other_order
                )
        c.demo_response = c.demo_response.replace("ORDER-A", app.own_order).replace(
            "ORDER-B", app.other_order
        )
        c.demo_safe_response = c.demo_safe_response.replace("ORDER-A", app.own_order)
        for call in c.demo_tools:
            order = call.get("arguments", {}).get("order_id")
            if order:
                call["arguments"]["order_id"] = (
                    app.own_order if order == "ORDER-A" else app.other_order
                )
        c.prompt = (
            c.prompt.replace("ORDER-A", app.own_order)
            .replace("ORDER-B", app.other_order)
            .replace("customer-alice", app.principal)
        )
        if not c.is_adversarial and app.scenario != "support":
            c.prompt = app.task
    return cases
