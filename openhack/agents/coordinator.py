"""
Coordinator agent that orchestrates the full vulnerability scan pipeline.
"""

import asyncio
import json
import logging
import re
from typing import Optional

from .base import BaseAgent
from .recon import ReconAgent
from .hunter_swarm import HunterSwarmAgent
from .validator_swarm import ValidatorSwarmAgent
from .hunter import HunterAgent
from .feature_hunter import FeatureHunterAgent
from .sandbox_verifier_swarm import SandboxVerifierSwarmAgent
from .browser_verifier_swarm import BrowserVerifierSwarmAgent
from .session import Session, Finding, SessionStatus
from .llm import LLMClient, Message
from .checkpoint import CheckpointManager
from openhack.sandbox.orchestrator import SandboxConfig
from openhack.prompts import COORDINATOR_PROMPT
from openhack.prompts.feature_hunter import FEATURE_EXTRACTION_PROMPT
from openhack.prompts.researchers import (
    HARDCODED_RESEARCHERS, C_RESEARCHERS, JAVA_RESEARCHERS,
    DOTNET_RESEARCHERS, RUST_RESEARCHERS, PROTOCOL_RESEARCHERS,
    RESEARCH_MANAGER_PROMPT,
)
from openhack.tools.registry import ToolRegistry
from openhack.tools.coverage import (
    discover_attack_surface,
    compute_coverage,
    enrich_missed_endpoints,
    build_second_pass_tasks,
    build_researcher_zones,
)
from openhack.categories import normalize_category, normalize_severity
from openhack.framework_detection import detect_frameworks
from openhack.quality import run_quality_gates
# Static validator removed — line number correction in hunter, semantic validation by LLM
from openhack.config import settings

logger = logging.getLogger(__name__)


    # _RESEARCHER_TASKS removed — now using HARDCODED_RESEARCHERS + manager-written tasks


class CoordinatorAgent(BaseAgent):
    name = "coordinator"
    description = "Orchestrating security scan"

    def __init__(self, llm: LLMClient, tools: ToolRegistry, session: Session, resume_from: Optional[str] = None):
        super().__init__(llm, tools, session)
        self.context: dict = {}
        self.checkpoint_mgr = CheckpointManager(session.id) if settings.checkpoint_enabled else None
        self.resume_from = resume_from

    def get_system_prompt(self, context: dict) -> str:
        detected = context.get("detected_frameworks", [])
        if detected:
            fw_names = [f["framework"] for f in detected]
            framework_context = "an application using " + ", ".join(fw_names)
        else:
            framework_context = "an application"
        return COORDINATOR_PROMPT.format(
            framework_context=framework_context,
            context=str(context),
            task="Coordinate the security scan",
        )

    def _create_llm_for_agent(self, agent_type: str) -> LLMClient:
        model_override = getattr(settings, f"{agent_type}_model_id", None)
        model = model_override or self.llm.model
        return LLMClient(model=model, temperature=0.0, max_tokens=8192, provider=self.llm.provider, prompt_cache_key=self.llm.prompt_cache_key)

    @staticmethod
    def _deduplicate_validated(validated, potential_findings):
        if len(validated) <= 1:
            return validated

        SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        seen = {}
        for v in validated:
            idx = v.get("original_index")
            if idx is None or idx < 0 or idx >= len(potential_findings):
                continue
            orig = potential_findings[idx]
            file_path = (orig.get("file_path") or "").strip().lower().split(":")[0]
            cat = normalize_category(orig.get("category", "")).lower()
            key = f"{file_path}::{cat}"

            if key not in seen:
                seen[key] = v
            else:
                existing_idx = seen[key].get("original_index", 0)
                existing_orig = potential_findings[existing_idx] if 0 <= existing_idx < len(potential_findings) else {}
                existing_sev = SEVERITY_ORDER.get((existing_orig.get("severity") or "info").lower(), 4)
                new_sev = SEVERITY_ORDER.get((orig.get("severity") or "info").lower(), 4)
                if (new_sev, -len(orig.get("description") or "")) < (existing_sev, -len(existing_orig.get("description") or "")):
                    seen[key] = v

        return list(seen.values())

    @staticmethod
    def _cap_findings_per_file(validated, potential_findings, max_per_file=3):
        if len(validated) <= max_per_file:
            return validated

        SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        by_file = {}
        for v in validated:
            idx = v.get("original_index")
            if idx is None or idx < 0 or idx >= len(potential_findings):
                continue
            orig = potential_findings[idx]
            file_path = (orig.get("file_path") or "").strip().lower().split(":")[0]
            by_file.setdefault(file_path, []).append(v)

        result = []
        for file_path, items in by_file.items():
            if len(items) <= max_per_file:
                result.extend(items)
            else:
                items.sort(key=lambda v: SEVERITY_ORDER.get(
                    (potential_findings[v["original_index"]].get("severity") or "info").lower(), 4
                ))
                result.extend(items[:max_per_file])
        return result

    def _build_checkpoint_data(
        self, total_cost: float, total_tokens: int,
        total_input_tokens: int, total_output_tokens: int,
        potential_findings: Optional[list] = None,
        all_files_analyzed: Optional[list] = None,
    ) -> dict:
        """Build a checkpoint data dict from current state."""
        data = {
            "context": self.context,
            "total_cost": total_cost,
            "total_tokens": total_tokens,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "step_costs": dict(self.session.step_costs),
            "step_tokens": dict(self.session.step_tokens),
            "step_input_tokens": dict(self.session.step_input_tokens),
            "step_output_tokens": dict(self.session.step_output_tokens),
        }
        if potential_findings is not None:
            data["potential_findings"] = potential_findings
        if all_files_analyzed is not None:
            data["all_files_analyzed"] = all_files_analyzed
        return data

    @staticmethod
    def _parse_json_array(raw: Optional[str], label: str = "response") -> list:
        """Extract a JSON array from an LLM response, handling common failures."""
        content = raw or ""
        if "```json" in content:
            content = content.split("```json", 1)[1].split("```", 1)[0]
        elif "```" in content:
            content = content.split("```", 1)[1].split("```", 1)[0]
        content = content.strip()

        # Direct parse
        try:
            result = json.loads(content)
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

        # Fix common issues: unescaped newlines, trailing commas
        fixed = re.sub(r'(?<!\\)\n', ' ', content)
        fixed = re.sub(r',\s*([}\]])', r'\1', fixed)
        try:
            result = json.loads(fixed)
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

        # Model returned reasoning text with JSON embedded — find the array
        bracket_pos = content.find("[")
        if bracket_pos > 0:
            candidate = content[bracket_pos:]
            depth = 0
            for i, ch in enumerate(candidate):
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        try:
                            result = json.loads(candidate[: i + 1])
                            if isinstance(result, list):
                                return result
                        except (json.JSONDecodeError, ValueError):
                            break

        logger.warning(f"Failed to parse {label} JSON: {content[:200]}")
        return []

    async def _extract_high_risk_features(self, recon_summary: str, attack_surface: Optional[dict] = None) -> list[dict]:
        """Extract high-risk features from recon output via a single LLM call."""
        attack_surface_str = ""
        if attack_surface:
            # Summarize key attack surface info for the extraction prompt
            parts = []
            for key in ("route_handlers", "api_routes", "danger_files"):
                entries = attack_surface.get(key, [])
                if entries:
                    files = [e.get("file", "") for e in entries[:20]]
                    parts.append(f"{key}: {', '.join(files)}")
            attack_surface_str = "\n".join(parts) if parts else "No attack surface data available."
        else:
            attack_surface_str = "No attack surface data available."

        # Extract just the high-risk areas and key sections to keep the prompt focused.
        # Full recon summaries can be 10k+ chars which causes some models to return
        # empty or truncated JSON responses.
        condensed = recon_summary
        if len(recon_summary) > 2000:
            sections = []
            for header in ["## High-Risk Areas", "## Application Overview",
                           "## Attacker Model Context"]:
                if header in recon_summary:
                    start = recon_summary.index(header)
                    next_header = recon_summary.find("\n## ", start + len(header))
                    end = next_header if next_header != -1 else min(start + 1000, len(recon_summary))
                    sections.append(recon_summary[start:end].strip())
            condensed = "\n\n".join(sections) if sections else recon_summary[:2000]
            # Hard cap
            if len(condensed) > 3000:
                condensed = condensed[:3000]

        prompt = FEATURE_EXTRACTION_PROMPT.format(
            recon_summary=condensed,
            attack_surface=attack_surface_str,
        )

        llm = LLMClient(
            model=settings.hunter_model_id or self.llm.model,
            temperature=0.0,
            max_tokens=4096,
            provider=self.llm.provider,
            prompt_cache_key=self.llm.prompt_cache_key,
        )
        full_prompt = (
            "You are a security analyst. Extract 3-5 high-risk features from the recon summary below.\n"
            "Return ONLY a valid JSON array. No markdown, no explanation, no code fences.\n"
            "Keep descriptions SHORT (under 20 words each). Keep risk_reason SHORT (under 20 words).\n"
            "entry_files should list 2-3 likely file paths.\n\n"
            + prompt
        )
        response = await llm.chat(
            messages=[Message(role="user", content=full_prompt)],
            tools=[],
            system=(
                "You are a JSON-only responder. Output ONLY a raw JSON array, nothing else. "
                "Do NOT include any reasoning, thinking, preamble, or explanation. "
                "The very first character of your response must be [."
            ),
        )

        features = self._parse_json_array(response.content, "feature extraction")

        # Cap to configured max
        features = features[:settings.max_feature_hunters]

        # Track the extraction cost
        self.session.total_cost += response.cost
        if response.usage:
            self.session.total_tokens += response.usage.get("total_tokens", 0)

        features = [f if isinstance(f, dict) else {"name": str(f), "description": str(f)} for f in features]
        logger.info(f"Extracted {len(features)} high-risk features: {[f.get('name', '?') for f in features]}")
        return features

    async def _write_app_specific_researchers(self, recon_summary: str) -> list[dict]:
        """Manager agent: reads recon and writes app-specific researcher tasks."""
        condensed = recon_summary
        if len(recon_summary) > 3000:
            sections = []
            for header in ["## High-Risk Areas", "## Application Overview",
                           "## Attacker Model Context"]:
                if header in recon_summary:
                    start = recon_summary.index(header)
                    next_header = recon_summary.find("\n## ", start + len(header))
                    end = next_header if next_header != -1 else min(start + 1000, len(recon_summary))
                    sections.append(recon_summary[start:end].strip())
            condensed = "\n\n".join(sections) if sections else recon_summary[:3000]

        prompt = RESEARCH_MANAGER_PROMPT.format(recon_summary=condensed)

        llm = LLMClient(
            model=settings.hunter_model_id or self.llm.model,
            temperature=0.0, max_tokens=4096, provider=self.llm.provider,
            prompt_cache_key=self.llm.prompt_cache_key,
        )
        full_prompt = (
            "You are a security research manager. Write 2-3 app-specific researcher tasks. "
            "Return ONLY a valid JSON array. No markdown, no code fences.\n\n" + prompt
        )
        response = await llm.chat(
            messages=[Message(role="user", content=full_prompt)],
            tools=[],
            system=(
                "You are a JSON-only responder. Output ONLY a raw JSON array, nothing else. "
                "Do NOT include any reasoning, thinking, preamble, or explanation. "
                "The very first character of your response must be [."
            ),
        )

        tasks = self._parse_json_array(response.content, "manager")

        self.session.total_cost += response.cost
        if response.usage:
            self.session.total_tokens += response.usage.get("total_tokens", 0)

        logger.info(f"Manager wrote {len(tasks)} app-specific researchers: {[t.get('name', '?') for t in tasks]}")
        return tasks

    async def _run_feature_deep_dive(self, features: list[dict], context: dict) -> dict:  # noqa: C901
        """Spawn feature hunters concurrently and collect their findings.

        If features is non-empty, spawns one hunter per feature (legacy mode).
        If features is empty, spawns researcher agents that pick their own targets.

        When zone-scoped mode is active, returns a 'zone_results' list mapping
        each zone to its researcher's findings and analyzed files — used by
        callers (headless_scan) to update ScanSession zone coverage.
        """
        semaphore = asyncio.Semaphore(settings.max_concurrent_feature_hunters)
        total_cost = 0.0
        total_tokens = 0
        total_input_tokens = 0
        total_output_tokens = 0
        zone_map: dict[int, dict] = {}  # hunter_id -> zone metadata

        async def run_hunter(feature: dict = None, hunter_id: int = 0):
            async with semaphore:
                model = settings.feature_hunter_model_id or settings.hunter_model_id or self.llm.model
                llm = LLMClient(model=model, temperature=0.0, max_tokens=8192, provider=self.llm.provider, prompt_cache_key=self.llm.prompt_cache_key)
                hunter = FeatureHunterAgent(llm, self.tools, self.session, feature=feature, hunter_id=hunter_id)
                name = hunter.name
                try:
                    if feature:
                        task_text = (
                            f"Deep security audit of the {feature['name']} feature. "
                            f"Description: {feature.get('description', '')}. "
                            f"Risk: {feature.get('risk_reason', '')}."
                        )
                    else:
                        task_text = researcher_tasks.get(hunter_id, list(researcher_tasks.values())[0])
                    result = await hunter.run(task_text, context=context)
                    return name, result, llm, hunter_id
                except Exception as e:
                    logger.error(f"Feature hunter {name} failed: {e}")
                    return name, {"findings": [], "files_analyzed": []}, llm, hunter_id

        if features:
            tasks = [asyncio.create_task(run_hunter(feature=f)) for f in features]
        else:
            researcher_tasks: dict[int, str] = {}
            idx = 0

            # Try zone-scoped mode for large repos
            attack_surface = context.get("attack_surface") or self.context.get("attack_surface")
            zones = []
            if attack_surface:
                zones = build_researcher_zones(attack_surface, num_zones=settings.max_feature_hunters)

            if zones:
                # Zone-scoped mode: each researcher gets a dedicated file zone
                total_zone_files = sum(z["file_count"] for z in zones)
                logger.info(f"Zone-scoped researchers: {len(zones)} zones, {total_zone_files} files")
                self.session.add_trace(
                    agent="coordinator", event_type="status",
                    content=f"Zone-scoped mode: {len(zones)} zones covering {total_zone_files} files",
                )

                for zone in zones:
                    task_text = (
                        zone["scope_text"] + "\n\n---\n\n"
                        "Hunt for ALL vulnerability types in these files:\n"
                        "- Injection (SQL, command, template/SSTI, LDAP)\n"
                        "- XSS (stored, reflected, DOM, dangerouslySetInnerHTML, |safe)\n"
                        "- SSRF (user-controlled outbound requests, webhooks, URL fetching)\n"
                        "- Auth/Authz bypass, IDOR (missing ownership checks), privilege escalation\n"
                        "- Path traversal and file inclusion\n"
                        "- Data exposure, hardcoded secrets, verbose errors\n"
                        "- Business logic flaws, race conditions, non-atomic operations\n"
                        "- Framework-specific: ORM escape hatches, unsafe deserialization, mass assignment\n\n"
                        "For each file: read it fully, check authorization, trace user input to sinks, "
                        "follow imports to understand validation logic, and report confirmed vulnerabilities."
                    )
                    researcher_tasks[idx] = task_text
                    zone_map[idx] = {"name": zone["name"], "file_paths": zone.get("file_paths", set())}
                    idx += 1

                # Fill remaining slots with manager-written app-specific researchers
                recon_summary = context.get("recon", {}).get("summary", "")
                if recon_summary and idx < settings.max_feature_hunters:
                    try:
                        app_specific = await self._write_app_specific_researchers(recon_summary)
                        for task_def in app_specific:
                            if isinstance(task_def, dict) and "task" in task_def and idx < settings.max_feature_hunters:
                                researcher_tasks[idx] = task_def["task"]
                                logger.info(f"Manager-written researcher {idx}: {task_def.get('name', '?')}")
                                idx += 1
                    except Exception as e:
                        logger.warning(f"Manager agent failed: {e}")
            else:
                # Small repo mode: specialization-based researchers
                detected_frameworks = context.get("detected_frameworks", context.get("recon", {}).get("frameworks", []))
                framework_names = set(
                    f.get("framework", "")
                    for f in (detected_frameworks if isinstance(detected_frameworks, list) else [])
                )

                if framework_names & {"c", "cpp"}:
                    base_researchers = C_RESEARCHERS
                elif framework_names & {"java", "spring", "springboot"}:
                    base_researchers = JAVA_RESEARCHERS
                elif framework_names & {"dotnet", "csharp", "aspnet"}:
                    base_researchers = DOTNET_RESEARCHERS
                elif framework_names & {"rust"}:
                    base_researchers = RUST_RESEARCHERS
                else:
                    base_researchers = HARDCODED_RESEARCHERS

                for name, task_text in base_researchers.items():
                    researcher_tasks[idx] = task_text
                    idx += 1

                recon_features = context.get("recon", {}).get("features", {})
                if isinstance(recon_features, dict):
                    feature_keys = set(recon_features.keys())
                    if "websocket" in feature_keys or any("websocket" in str(v).lower() for v in recon_features.values()):
                        researcher_tasks[idx] = PROTOCOL_RESEARCHERS.get("websocket", "")
                        idx += 1
                    if "grpc" in feature_keys or any("grpc" in str(v).lower() for v in recon_features.values()):
                        researcher_tasks[idx] = PROTOCOL_RESEARCHERS.get("grpc", "")
                        idx += 1

                recon_summary = context.get("recon", {}).get("summary", "")
                if recon_summary:
                    try:
                        app_specific = await self._write_app_specific_researchers(recon_summary)
                        for task_def in app_specific:
                            if isinstance(task_def, dict) and "task" in task_def:
                                researcher_tasks[idx] = task_def["task"]
                                logger.info(f"Manager-written researcher {idx}: {task_def.get('name', '?')}")
                                idx += 1
                    except Exception as e:
                        logger.warning(f"Manager agent failed: {e}")

            num_researchers = min(len(researcher_tasks), settings.max_feature_hunters)
            tasks = [asyncio.create_task(run_hunter(hunter_id=i)) for i in range(num_researchers)]

        try:
            results = await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        all_findings = []
        all_files = set()
        zone_results = []
        for name, result, llm_client, hunter_id in results:
            findings = result.get("findings", [])
            files_analyzed = result.get("files_analyzed", [])
            all_findings.extend(findings)
            all_files.update(files_analyzed)
            total_cost += llm_client.total_cost
            total_tokens += llm_client.total_tokens
            total_input_tokens += llm_client.total_input_tokens
            total_output_tokens += llm_client.total_output_tokens
            logger.info(f"Feature hunter {name}: {len(findings)} findings")

            if hunter_id in zone_map:
                zone_results.append({
                    "zone_name": zone_map[hunter_id]["name"],
                    "zone_file_paths": list(zone_map[hunter_id].get("file_paths", [])),
                    "files_analyzed": files_analyzed,
                    "findings_count": len(findings),
                })

        # Deduplicate
        all_findings = HunterSwarmAgent._deduplicate_findings(all_findings)

        result_dict = {
            "findings": all_findings,
            "files_analyzed": sorted(all_files),
            "total_cost": total_cost,
            "total_tokens": total_tokens,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
        }
        if zone_results:
            result_dict["zone_results"] = zone_results
        return result_dict

    async def run_full_scan(self) -> dict:
        self.session.status = SessionStatus.RUNNING

        total_cost = 0.0
        total_tokens = 0
        total_input_tokens = 0
        total_output_tokens = 0
        potential_findings: list = []
        all_files_analyzed: list = []

        # ── Resume from checkpoint ──────────────────────────────────────
        skip_to: Optional[str] = None
        if self.resume_from and self.checkpoint_mgr:
            checkpoint = self.checkpoint_mgr.load(self.resume_from)
            if checkpoint:
                data = checkpoint["data"]
                self.context = data.get("context", {})
                self.session.context = dict(self.context)
                self.session.restore_from_checkpoint(data)
                total_cost = data.get("total_cost", 0.0)
                total_tokens = data.get("total_tokens", 0)
                total_input_tokens = data.get("total_input_tokens", 0)
                total_output_tokens = data.get("total_output_tokens", 0)

                if self.resume_from == "recon":
                    skip_to = "hunter"
                elif self.resume_from == "hunter":
                    skip_to = "validator"
                    potential_findings = data.get("potential_findings", [])
                    all_files_analyzed = data.get("all_files_analyzed", [])
                elif self.resume_from == "feature_hunt":
                    skip_to = "validator"
                    potential_findings = data.get("potential_findings", [])
                    all_files_analyzed = data.get("all_files_analyzed", [])

                logger.info(f"Resuming from checkpoint '{self.resume_from}', skipping to: {skip_to}")
                self.session.add_trace(
                    agent="coordinator", event_type="resume",
                    content={"from_checkpoint": self.resume_from, "skip_to": skip_to},
                )

        # Project context: always use the current session's value (survives resume)
        if self.session.project_context:
            self.context["project_context"] = self.session.project_context

        # Framework detection (deterministic) — skip if restored from checkpoint
        if "detected_frameworks" not in self.context:
            detected_frameworks = detect_frameworks(self.tools.fs_tools)
            self.context["detected_frameworks"] = detected_frameworks
            self.session.context["detected_frameworks"] = detected_frameworks
            logger.info(f"Detected frameworks: {[f['framework'] for f in detected_frameworks]}")

        try:
            # Attack surface discovery (deterministic)
            attack_surface = self.context.get("attack_surface")
            if attack_surface is None:
                try:
                    attack_surface = discover_attack_surface(self.tools.fs_tools, nextjs_tools=self.tools.nextjs_tools)
                    self.context["attack_surface"] = attack_surface
                    logger.info(f"Attack surface: {attack_surface['total_endpoints']} endpoints")
                except Exception as e:
                    logger.warning(f"Attack surface discovery failed: {e}")

            # Step 1: Reconnaissance
            if skip_to is None:
                self.session.add_trace(agent="coordinator", event_type="step_start", content="Step 1: Reconnaissance")
                recon_llm = self._create_llm_for_agent("recon")
                recon_agent = ReconAgent(recon_llm, self.tools, self.session)
                recon_result = await recon_agent.run(
                    "Perform reconnaissance on this application. Map out the structure, "
                    "identify authentication mechanisms, API surface, and high-risk areas.",
                    context=self.context,
                )
                self.context["recon"] = recon_result
                self.session.context["recon"] = recon_result

                recon_cost = recon_llm.total_cost
                recon_tokens = recon_llm.total_tokens
                self.session.record_step_cost("recon", recon_cost, recon_tokens,
                    input_tokens=recon_llm.total_input_tokens, output_tokens=recon_llm.total_output_tokens)
                total_cost += recon_cost
                total_tokens += recon_tokens
                total_input_tokens += recon_llm.total_input_tokens
                total_output_tokens += recon_llm.total_output_tokens
                self.session.total_cost = total_cost
                self.session.total_tokens = total_tokens
                self.session.add_trace(agent="coordinator", event_type="step_complete",
                    content={"step": "recon", "cost": recon_cost, "tokens": recon_tokens,
                             "input_tokens": recon_llm.total_input_tokens, "output_tokens": recon_llm.total_output_tokens})

                # Checkpoint: recon complete
                if self.checkpoint_mgr:
                    self.checkpoint_mgr.save("recon", self._build_checkpoint_data(
                        total_cost, total_tokens, total_input_tokens, total_output_tokens))

            # Step 2: Hunting (swarm)
            if skip_to in (None, "hunter"):
                self.session.add_trace(agent="coordinator", event_type="step_start", content="Step 2: Hunting (swarm)")
                hunter_llm = self._create_llm_for_agent("hunter")
                hunter_swarm = HunterSwarmAgent(hunter_llm, self.tools, self.session)
                hunter_result = await hunter_swarm.run(
                    "Hunt for security vulnerabilities in this application.", context=self.context)
                self.context["hunter"] = hunter_result
                self.session.context["hunter"] = hunter_result

                hunter_cost = hunter_swarm.total_cost
                hunter_tokens = hunter_swarm.total_tokens
                self.session.record_step_cost("hunter", hunter_cost, hunter_tokens,
                    input_tokens=hunter_swarm.total_input_tokens, output_tokens=hunter_swarm.total_output_tokens)
                total_cost += hunter_cost
                total_tokens += hunter_tokens
                total_input_tokens += hunter_swarm.total_input_tokens
                total_output_tokens += hunter_swarm.total_output_tokens
                self.session.total_cost = total_cost
                self.session.total_tokens = total_tokens

                potential_findings = hunter_result.get("findings", [])
                all_files_analyzed = list(hunter_result.get("files_analyzed", []))
                self.session.add_trace(agent="coordinator", event_type="step_complete",
                    content={"step": "hunter_swarm", "cost": hunter_cost, "tokens": hunter_tokens,
                             "potential_findings": len(potential_findings)})

                # Step 2.5: Coverage-guided second pass
                if attack_surface:
                    pass1_coverage = compute_coverage(attack_surface, all_files_analyzed)
                    missed_endpoints = pass1_coverage.get("missed", [])

                    if missed_endpoints:
                        self.session.add_trace(agent="coordinator", event_type="step_start",
                            content=f"Step 2.5: Coverage second pass ({len(missed_endpoints)} missed)")

                        enriched = enrich_missed_endpoints(missed_endpoints, self.tools.fs_tools)
                        second_pass_tasks = build_second_pass_tasks(enriched)

                        pass2_findings = []
                        pass2_files = set()
                        pass2_cost = 0.0
                        pass2_tokens = 0
                        pass2_input = 0
                        pass2_output = 0

                        sem = asyncio.Semaphore(settings.max_concurrent_hunters)

                        async def run_pass2(task_text, batch_idx):
                            async with sem:
                                llm = self._create_llm_for_agent("hunter")
                                hunter = HunterAgent(llm, self.tools, self.session,
                                    vuln_categories=["xss", "injection", "ssrf", "open_redirect", "idor", "auth_bypass"],
                                    group_name=f"second_pass_{batch_idx}")
                                try:
                                    result = await hunter.run(task_text, self.context)
                                    return result, hunter.llm
                                except Exception as e:
                                    logger.error(f"Second pass hunter {batch_idx} failed: {e}")
                                    return {"findings": [], "files_analyzed": []}, hunter.llm

                        pass2_tasks = [
                            asyncio.create_task(run_pass2(t, i))
                            for i, t in enumerate(second_pass_tasks)
                        ]
                        try:
                            pass2_results = await asyncio.gather(*pass2_tasks)
                        except asyncio.CancelledError:
                            for t in pass2_tasks:
                                t.cancel()
                            await asyncio.gather(*pass2_tasks, return_exceptions=True)
                            raise

                        for result, llm_client in pass2_results:
                            pass2_findings.extend(result.get("findings", []))
                            pass2_files.update(result.get("files_analyzed", []))
                            pass2_cost += llm_client.total_cost
                            pass2_tokens += llm_client.total_tokens
                            pass2_input += llm_client.total_input_tokens
                            pass2_output += llm_client.total_output_tokens

                        self.session.record_step_cost("hunter_second_pass", pass2_cost, pass2_tokens,
                            input_tokens=pass2_input, output_tokens=pass2_output)
                        total_cost += pass2_cost
                        total_tokens += pass2_tokens
                        self.session.total_cost = total_cost
                        self.session.total_tokens = total_tokens

                        potential_findings.extend(pass2_findings)
                        all_files_analyzed = sorted(set(all_files_analyzed) | pass2_files)
                        hunter_result["findings"] = potential_findings
                        hunter_result["files_analyzed"] = all_files_analyzed
                        self.context["hunter"] = hunter_result

                        self.session.add_trace(agent="coordinator", event_type="step_complete",
                            content={"step": "hunter_second_pass", "cost": pass2_cost, "tokens": pass2_tokens,
                                     "new_findings": len(pass2_findings), "total_findings": len(potential_findings)})

                # Checkpoint: hunter complete (includes second pass)
                if self.checkpoint_mgr:
                    self.checkpoint_mgr.save("hunter", self._build_checkpoint_data(
                        total_cost, total_tokens, total_input_tokens, total_output_tokens,
                        potential_findings=potential_findings, all_files_analyzed=all_files_analyzed))

            # Step 2.25: Feature Deep Dive
            if settings.feature_hunt_enabled and skip_to in (None, "hunter"):
                recon_summary = self.context.get("recon", {}).get("summary", "")
                if recon_summary:
                    self.session.add_trace(
                        agent="coordinator", event_type="step_start",
                        content="Step 2.25: Feature deep dive — extracting high-risk features",
                    )

                    features = await self._extract_high_risk_features(
                        recon_summary, attack_surface,
                    )

                    if features:
                        self.session.add_trace(
                            agent="coordinator", event_type="status",
                            content=f"Feature deep dive: {len(features)} features — "
                                    + ", ".join(f.get("name", "?") for f in features),
                        )
                    else:
                        # Researcher mode: agents pick their own targets
                        logger.info("No features extracted — spawning researcher agents")
                        self.session.add_trace(
                            agent="coordinator", event_type="status",
                            content="Feature deep dive: researcher mode — agents pick their own targets",
                        )

                    feature_result = await self._run_feature_deep_dive(features, self.context)

                    feature_findings = feature_result.get("findings", [])
                    feature_cost = feature_result["total_cost"]
                    feature_tokens = feature_result["total_tokens"]

                    self.session.record_step_cost(
                        "feature_hunt", feature_cost, feature_tokens,
                        input_tokens=feature_result["total_input_tokens"],
                        output_tokens=feature_result["total_output_tokens"],
                    )
                    total_cost += feature_cost
                    total_tokens += feature_tokens
                    total_input_tokens += feature_result["total_input_tokens"]
                    total_output_tokens += feature_result["total_output_tokens"]
                    self.session.total_cost = total_cost
                    self.session.total_tokens = total_tokens

                    # Merge and deduplicate with category hunter findings
                    potential_findings.extend(feature_findings)
                    potential_findings = HunterSwarmAgent._deduplicate_findings(potential_findings)
                    all_files_analyzed = sorted(
                        set(all_files_analyzed) | set(feature_result.get("files_analyzed", []))
                    )

                    if "hunter" not in self.context:
                        self.context["hunter"] = {}
                    self.context["hunter"]["findings"] = potential_findings
                    self.context["hunter"]["files_analyzed"] = all_files_analyzed

                    self.session.add_trace(
                        agent="coordinator", event_type="step_complete",
                        content={
                            "step": "feature_hunt",
                            "features_analyzed": len(features),
                            "new_findings": len(feature_findings),
                            "total_findings": len(potential_findings),
                            "cost": feature_cost,
                            "tokens": feature_tokens,
                        },
                    )

                    # Checkpoint: feature hunt complete
                    if self.checkpoint_mgr:
                        self.checkpoint_mgr.save("feature_hunt", self._build_checkpoint_data(
                            total_cost, total_tokens, total_input_tokens, total_output_tokens,
                            potential_findings=potential_findings, all_files_analyzed=all_files_analyzed))

            # Pass findings directly to LLM validation (static validator removed —
            # line number correction now happens in _handle_report_finding,
            # and all semantic judgment is left to the LLM validator)
            if "hunter" not in self.context:
                self.context["hunter"] = {}
            self.context["hunter"]["findings"] = potential_findings

            # Step 3: Validation (swarm)
            if potential_findings:
                self.session.add_trace(agent="coordinator", event_type="step_start", content="Step 3: Validation (swarm)")
                validator_llm = self._create_llm_for_agent("validator")
                validator_swarm = ValidatorSwarmAgent(validator_llm, self.tools, self.session)
                validator_result = await validator_swarm.run(
                    "Validate each potential vulnerability.", context=self.context)
                self.context["validator"] = validator_result

                validator_cost = validator_swarm.total_cost
                validator_tokens = validator_swarm.total_tokens
                self.session.record_step_cost("validator", validator_cost, validator_tokens,
                    input_tokens=validator_swarm.total_input_tokens, output_tokens=validator_swarm.total_output_tokens)
                total_cost += validator_cost
                total_tokens += validator_tokens
                self.session.total_cost = total_cost
                self.session.total_tokens = total_tokens

                validated = validator_result.get("validated_findings", [])
                self.session.add_trace(agent="coordinator", event_type="step_complete",
                    content={"step": "validator_swarm", "cost": validator_cost, "tokens": validator_tokens,
                             "validated_findings": len(validated)})

                # Post-processing
                validated = self._deduplicate_validated(validated, potential_findings)
                validated = self._cap_findings_per_file(validated, potential_findings, max_per_file=3)

                # Severity normalization
                orig_for_norm = []
                for v in validated:
                    idx = v.get("original_index")
                    if idx is not None and 0 <= idx < len(potential_findings):
                        orig_for_norm.append(potential_findings[idx])
                    else:
                        orig_for_norm.append({})
                normalised = normalize_severity(orig_for_norm)
                for i, v in enumerate(validated):
                    idx = v.get("original_index")
                    if idx is not None and 0 <= idx < len(potential_findings):
                        potential_findings[idx]["severity"] = normalised[i].get("severity", potential_findings[idx].get("severity", "medium"))

                # Quality gates
                validated, quality_stats = run_quality_gates(validated, potential_findings, fs_tools=self.tools.fs_tools)

                # Create Finding objects
                for finding_data in validated:
                    original_index = finding_data.get("original_index")
                    if original_index is None or original_index < 0 or original_index >= len(potential_findings):
                        continue
                    orig = potential_findings[original_index]

                    finding = Finding(
                        category=orig.get("category", "unknown"),
                        severity=orig.get("severity", "medium"),
                        title=f"{orig.get('category', 'Unknown')} in {orig.get('file_path', 'unknown')}",
                        description=orig.get("description", ""),
                        file_path=orig.get("file_path", ""),
                        line_number=orig.get("line_number"),
                        code_snippet=orig.get("code_snippet"),
                        poc=finding_data.get("poc"),
                        fix=finding_data.get("fix"),
                        cvss_score=finding_data.get("cvss_score"),
                        confidence=finding_data.get("confidence", "medium"),
                        validated=True,
                    )
                    self.session.add_finding(finding)
                    self.session.add_trace(agent="coordinator", event_type="finding_added",
                        content={"title": finding.title, "category": finding.category,
                                 "severity": finding.severity, "file_path": finding.file_path})
            else:
                self.context["validator"] = {"validated_findings": [], "false_positives": []}

            # Step 4: Sandbox Verification (optional)
            if settings.sandbox_enabled and self.session.findings:
                self.session.add_trace(
                    agent="coordinator", event_type="step_start",
                    content=f"Step 4: Sandbox verification ({len(self.session.findings)} findings)",
                )

                # Build confirmed findings list for the sandbox swarm
                confirmed_findings = []
                for finding in self.session.findings:
                    confirmed_findings.append({
                        "category": finding.category,
                        "severity": finding.severity,
                        "title": finding.title,
                        "description": finding.description,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "code_snippet": finding.code_snippet,
                        "poc": finding.poc,
                        "fix": finding.fix,
                        "cvss_score": finding.cvss_score,
                        "confidence": finding.confidence,
                    })

                sandbox_config = SandboxConfig(
                    health_check_path=settings.sandbox_health_check_path,
                    health_check_timeout=settings.sandbox_health_check_timeout,
                    teardown_on_complete=settings.sandbox_teardown_on_complete,
                )

                sandbox_llm = self._create_llm_for_agent("validator")
                sandbox_swarm = SandboxVerifierSwarmAgent(
                    sandbox_llm, self.tools, self.session,
                    sandbox_config=sandbox_config,
                )

                sandbox_context = {
                    "confirmed_findings": confirmed_findings,
                    "project_context": self.context.get("project_context", {}),
                }

                try:
                    sandbox_result = await sandbox_swarm.run(
                        "Verify confirmed findings by exploiting them in the sandbox.",
                        context=sandbox_context,
                    )
                    self.context["sandbox_verification"] = sandbox_result

                    sandbox_cost = sandbox_swarm.total_cost
                    sandbox_tokens = sandbox_swarm.total_tokens
                    self.session.record_step_cost(
                        "sandbox_verification", sandbox_cost, sandbox_tokens,
                        input_tokens=sandbox_swarm.total_input_tokens,
                        output_tokens=sandbox_swarm.total_output_tokens,
                    )
                    total_cost += sandbox_cost
                    total_tokens += sandbox_tokens
                    self.session.total_cost = total_cost
                    self.session.total_tokens = total_tokens

                    # Update findings with sandbox verification results
                    exploitable = sandbox_result.get("exploitable", [])
                    not_exploitable = sandbox_result.get("not_exploitable", [])

                    exploitable_indices = {
                        r.get("finding_index") for r in exploitable
                    }

                    for r in exploitable:
                        idx = r.get("finding_index")
                        if idx is not None and idx < len(self.session.findings):
                            finding = self.session.findings[idx]
                            # Upgrade the PoC with the working exploit
                            if r.get("working_poc"):
                                finding.poc = r["working_poc"]
                            finding.validated = True
                            finding.source = "sandbox_verified"

                    # Remove findings that couldn't be exploited in sandbox
                    if not_exploitable:
                        not_exploitable_indices = {
                            r.get("finding_index") for r in not_exploitable
                            if r.get("confidence") == "high"
                        }
                        # Only remove high-confidence non-exploitable findings
                        self.session.findings = [
                            f for i, f in enumerate(self.session.findings)
                            if i not in not_exploitable_indices
                        ]

                    self.session.add_trace(
                        agent="coordinator", event_type="step_complete",
                        content={
                            "step": "sandbox_verification",
                            "exploitable": len(exploitable),
                            "not_exploitable": len(not_exploitable),
                            "cost": sandbox_cost,
                            "tokens": sandbox_tokens,
                        },
                    )

                except Exception as e:
                    logger.debug(f"Sandbox verification failed: {e}", exc_info=True)
                    self.session.add_trace(
                        agent="coordinator", event_type="sandbox_error",
                        content=f"Sandbox verification failed: {str(e)}. Findings preserved without sandbox verification.",
                    )

            # Step 5: Browser Verification (optional)
            if settings.browser_verification_enabled and self.session.findings:
                self.session.add_trace(
                    agent="coordinator", event_type="step_start",
                    content=f"Step 5: Browser verification ({len(self.session.findings)} findings)",
                )

                confirmed_findings = []
                for finding in self.session.findings:
                    confirmed_findings.append({
                        "category": finding.category,
                        "severity": finding.severity,
                        "title": finding.title,
                        "description": finding.description,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "code_snippet": finding.code_snippet,
                        "poc": finding.poc,
                        "fix": finding.fix,
                        "cvss_score": finding.cvss_score,
                        "confidence": finding.confidence,
                    })

                sandbox_config = SandboxConfig(
                    health_check_path=settings.sandbox_health_check_path,
                    health_check_timeout=settings.sandbox_health_check_timeout,
                    teardown_on_complete=settings.sandbox_teardown_on_complete,
                )

                browser_llm = self._create_llm_for_agent("validator")
                browser_swarm = BrowserVerifierSwarmAgent(
                    browser_llm, self.tools, self.session,
                    sandbox_config=sandbox_config,
                )

                browser_context = {
                    "confirmed_findings": confirmed_findings,
                    "project_context": self.context.get("project_context", {}),
                }

                try:
                    browser_result = await browser_swarm.run(
                        "Verify confirmed findings using browser-based exploit verification.",
                        context=browser_context,
                    )
                    self.context["browser_verification"] = browser_result

                    browser_cost = browser_swarm.total_cost
                    browser_tokens = browser_swarm.total_tokens
                    self.session.record_step_cost(
                        "browser_verification", browser_cost, browser_tokens,
                        input_tokens=browser_swarm.total_input_tokens,
                        output_tokens=browser_swarm.total_output_tokens,
                    )
                    total_cost += browser_cost
                    total_tokens += browser_tokens
                    self.session.total_cost = total_cost
                    self.session.total_tokens = total_tokens

                    exploitable = browser_result.get("exploitable", [])
                    not_exploitable = browser_result.get("not_exploitable", [])

                    for r in exploitable:
                        idx = r.get("finding_index")
                        if idx is not None and idx < len(self.session.findings):
                            finding = self.session.findings[idx]
                            finding.validated = True
                            finding.source = "browser_verified"

                    if not_exploitable:
                        not_exploitable_indices = {
                            r.get("finding_index") for r in not_exploitable
                            if r.get("confidence") == "high"
                        }
                        self.session.findings = [
                            f for i, f in enumerate(self.session.findings)
                            if i not in not_exploitable_indices
                        ]

                    self.session.add_trace(
                        agent="coordinator", event_type="step_complete",
                        content={
                            "step": "browser_verification",
                            "exploitable": len(exploitable),
                            "not_exploitable": len(not_exploitable),
                            "evidence_dir": browser_result.get("evidence_dir", ""),
                            "cost": browser_cost,
                            "tokens": browser_tokens,
                        },
                    )

                except ImportError as e:
                    logger.warning(f"Browser verification skipped: {e}")
                    self.session.add_trace(
                        agent="coordinator", event_type="browser_skip",
                        content=f"Browser verification skipped: {str(e)}",
                    )
                except Exception as e:
                    logger.debug(f"Browser verification failed: {e}", exc_info=True)
                    self.session.add_trace(
                        agent="coordinator", event_type="browser_error",
                        content=f"Browser verification failed: {str(e)}. Findings preserved.",
                    )

            self.session.status = SessionStatus.COMPLETED

            # Clean up checkpoints on successful completion
            if self.checkpoint_mgr:
                self.checkpoint_mgr.cleanup()

            coverage_data = None
            if attack_surface:
                coverage_data = compute_coverage(attack_surface, all_files_analyzed)

            cost_breakdown = self.session.get_cost_breakdown()
            self.session.add_trace(agent="coordinator", event_type="scan_complete",
                content={"findings_count": len(self.session.findings), "total_cost": self.session.total_cost,
                         "total_tokens": self.session.total_tokens, "cost_breakdown": cost_breakdown,
                         "coverage_pct": coverage_data["coverage_pct"] if coverage_data else None})

            return {
                "status": "completed",
                "findings": self.session.get_findings_dict(),
                "context": self.context,
                "total_cost": self.session.total_cost,
                "total_tokens": self.session.total_tokens,
                "cost_breakdown": cost_breakdown,
                "coverage_data": coverage_data,
            }

        except Exception as e:
            self.session.status = SessionStatus.FAILED
            logger.debug(f"Scan failed: {e}", exc_info=True)
            raise

    async def run(self, task: str, context: Optional[dict] = None) -> dict:
        return await self.run_full_scan()
