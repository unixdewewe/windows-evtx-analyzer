"""TaskScheduler, GroupPolicy, and AppLocker log normalizer."""

from typing import Any, Dict
from src.normalizers.base import BaseNormalizer


class PersistenceNormalizer(BaseNormalizer):
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event = self.base_schema(raw_event, category="Persistence/Policy")
        eid = raw_event.get("EventID")
        data = raw_event.get("EventData", {})

        task_name = data.get("TaskName") or data.get("Name")
        user_ctx = data.get("UserContext") or data.get("UserName")
        event["user"] = user_ctx
        event["summary"] = f"Persistence/Policy Event {eid}: Task/Object={task_name} User={user_ctx}"
        return event
