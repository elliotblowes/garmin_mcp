"""
Gemini-powered coach chat: reasons over the user's current plan and recent
Garmin data, and can propose structured edits to the plan for the user to
confirm — it never writes to the plan directly.
"""

import os
import json
from google import genai
from google.genai import types

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    return _client


PROPOSE_EDITS_SCHEMA = {
    "name": "propose_plan_edits",
    "description": "Propose one or more changes to specific days in the training plan, for the user to confirm before anything is saved.",
    "parameters": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "One short sentence summarizing the proposed change, shown to the user."},
            "edits": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "target_date": {"type": "string", "description": "The existing date (YYYY-MM-DD) of the day being changed."},
                        "type": {"type": "string", "enum": ["long", "quality", "easy", "strength", "rest", "race"]},
                        "description": {"type": "string"},
                        "badge": {"type": "string"},
                        "note": {"type": "string"},
                    },
                    "required": ["target_date", "type", "description"],
                },
            },
        },
        "required": ["summary", "edits"],
    },
}


def _build_context(plan: dict, garmin_snapshot: dict) -> str:
    return (
        f"Today's date: {garmin_snapshot.get('as_of', 'unknown')}\n\n"
        f"Current training plan (JSON):\n{json.dumps(plan)}\n\n"
        f"Recent Garmin data (last 10 days):\n{json.dumps(garmin_snapshot)}\n\n"
        "You are a supportive, honest running coach. Answer the user's message using "
        "this real data. If — and only if — a plan change genuinely makes sense based "
        "on what the user said or what the data shows, call propose_plan_edits with the "
        "specific day(s) to change. To move a workout from one day to another, propose "
        "two edits: update the origin day to 'rest' (or swap), and update the target day "
        "with the moved workout's details. Do not call the function for simple questions "
        "that don't require a plan change."
    )


def chat(message: str, history: list[dict], plan: dict, garmin_snapshot: dict) -> dict:
    """Returns {"reply": str, "proposed_edits": {"summary": str, "edits": [...]} | None}"""
    client = _get_client()

    contents = [_build_context(plan, garmin_snapshot)]
    for turn in history:
        role = "user" if turn.get("role") == "user" else "model"
        contents.append(types.Content(role=role, parts=[types.Part(text=turn.get("text", ""))]))
    contents.append(types.Content(role="user", parts=[types.Part(text=message)]))

    tool = types.Tool(function_declarations=[PROPOSE_EDITS_SCHEMA])

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=contents,
        config=types.GenerateContentConfig(tools=[tool]),
    )

    candidate = response.candidates[0]
    proposed_edits = None
    reply_text = ""

    for part in candidate.content.parts:
        if part.function_call and part.function_call.name == "propose_plan_edits":
            proposed_edits = dict(part.function_call.args)
        if part.text:
            reply_text += part.text

    if not reply_text and proposed_edits:
        reply_text = proposed_edits.get("summary", "I've proposed a change to your plan.")

    return {"reply": reply_text, "proposed_edits": proposed_edits}
